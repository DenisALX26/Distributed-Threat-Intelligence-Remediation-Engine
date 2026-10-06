package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/segmentio/kafka-go"
)

// ThreatPayload represents the incoming JSON structure
type ThreatPayload struct {
	Source      string `json:"source"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

func main() {
	// 1. Initialize the Kafka Writer
	// We connect to localhost:9094 because this Go code is running on your host machine, not in Docker yet.
	kafkaWriter := &kafka.Writer{
		Addr:     kafka.TCP("localhost:9094"),
		Topic:    "raw-threat-intel",
		Balancer: &kafka.LeastBytes{},
	}
	defer kafkaWriter.Close()

	// 2. Setup the HTTP Router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// 3. Define the Ingestion Endpoint
	r.Post("/api/v1/threats", func(w http.ResponseWriter, r *http.Request) {
		var payload ThreatPayload
		
		// Decode incoming JSON
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		// Convert struct back to JSON bytes for Kafka
		messageBytes, err := json.Marshal(payload)
		if err != nil {
			http.Error(w, "Failed to process payload", http.StatusInternalServerError)
			return
		}

		// Publish to Kafka
		err = kafkaWriter.WriteMessages(context.Background(),
			kafka.Message{
				Key:   []byte(payload.Source), // Partitioning key
				Value: messageBytes,
			},
		)

		if err != nil {
			log.Printf("Failed to write message to Kafka: %v", err)
			http.Error(w, "Failed to ingest threat data", http.StatusInternalServerError)
			return
		}

		// Send success response to client
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status": "accepted", "message": "Threat data ingested successfully"}`))
	})

	// 4. Start the Server
	port := ":8081"
	fmt.Printf("Aegis Ingestion Gateway running on port %s...\n", port)
	log.Fatal(http.ListenAndServe(port, r))
}