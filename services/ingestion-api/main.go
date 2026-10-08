package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/segmentio/kafka-go"
)

type ThreatPayload struct {
	Source      string `json:"source"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func main() {
	kafkaBroker := getEnv("KAFKA_BROKER", "localhost:9094")
	kafkaTopic := getEnv("KAFKA_TOPIC", "raw-threat-intel")

	kafkaWriter := &kafka.Writer{
		Addr:     kafka.TCP(kafkaBroker),
		Topic:    kafkaTopic,
		Balancer: &kafka.LeastBytes{},
	}
	defer kafkaWriter.Close()

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Post("/api/v1/threats", func(w http.ResponseWriter, r *http.Request) {
		var payload ThreatPayload
		
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		messageBytes, err := json.Marshal(payload)
		if err != nil {
			http.Error(w, "Failed to process payload", http.StatusInternalServerError)
			return
		}

		err = kafkaWriter.WriteMessages(context.Background(),
			kafka.Message{
				Key:   []byte(payload.Source),
				Value: messageBytes,
			},
		)

		if err != nil {
			log.Printf("Failed to write message to Kafka: %v", err)
			http.Error(w, "Failed to ingest threat data", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status": "accepted", "message": "Threat data ingested successfully"}`))
	})

	port := getEnv("PORT", ":8081")
	fmt.Printf("Aegis Ingestion Gateway running on port %s...\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}