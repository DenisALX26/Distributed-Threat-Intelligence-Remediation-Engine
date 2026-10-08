# Distributed Threat Intelligence & Remediation Engine

## The Problem
When a new software vulnerability hits the internet, hackers often exploit it before security teams even finish reading the documentation. Checking internal servers and writing firewall rules manually takes too much time.

## The Solution
This project is an automated, distributed security engine. It ingests unstructured threat alerts, uses an AI agent to check the internal infrastructure, and automatically generates a mitigation plan (including firewall scripts) without human intervention.

---

## Project Architecture

This project is built using different software engineering areas:

* **The Distributed Ingestion Layer (Backend & Distributed Systems):** A fast Go API receives threat alerts and sends them to an Apache Kafka queue. This prevents the system from crashing when too many alerts arrive at once.
* **The Security & Trust Layer (Security Engineering):** The AI does not have direct access to the database or servers. It uses the MCP to safely run specific tools, like generating `iptables` scripts.
* **The Data & State Layer (Data Engineering):** PostgreSQL stores the server inventory and the final AI reports. Kafka is configured for "at-least-once" delivery, meaning no data is lost if a container crashes.
* **The AI Reasoning Engine (AI Automations):** A Python worker uses Gemini AI to run a multi-turn "ReAct" loop. The AI thinks, calls tools, and checks the results before generating the final JSON plan.
* **The Infrastructure Layer (DevOps):** The entire system runs in Docker.

---

## Project Structure
```text
.
├── infrastructure
│   ├── docker-compose.yml
│   └── init.sql
├── README.md
└── services
    ├── analyzer-worker
    │   ├── db_init.py
    │   ├── db_seed.py
    │   ├── Dockerfile
    │   ├── main.py
    │   ├── mcp_server.py
    │   └── requirements.txt
    └── ingestion-api
        ├── Dockerfile
        ├── go.mod
        ├── go.sum
        └── main.go
```

---

## How to run the project

### 1. Setup Environment
Create a `.env` file in the analyzer-worker folder and copy the structure of `.env.example`

### 2. Start the containers
Build and run the project with Docker
```
docker compose up -d --build
```

### 3. Create the Kafka topic
Initialize the message queue
```
docker exec kafka kafka-topics --create \
  --topic raw-threat-intel \
  --bootstrap-server kafka:29092 \
  --partitions 1 \
  --replication-factor 1
```

### 4. Open the AI worker logs
Open a new terminal to see the logs in real time
```
docker logs -f analyzer-worker
```

### 5. Send a threat alert
Send a vulnerability to the Go API
```
curl -X POST http://localhost:8081/api/v1/threats \
  -H "Content-Type: application/json" \
  -d '{
    "source": "MITRE_ATT&CK",
    "description": "Zero-day path traversal vulnerability in Apache HTTP Server allowing arbitrary file read.",
    "severity": "CRITICAL"
  }'
```

### 6. Check the result
After the AI finishes in the logs, check the database to see the saved mitigation plan
```
docker exec -it postgres psql -U postgres -d aegis_db -c "SELECT id, source, risk_level, immediate_action_required FROM threat_intelligence ORDER BY id DESC LIMIT 1;"
```
