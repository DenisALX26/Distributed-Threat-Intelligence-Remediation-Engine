import os
import json
import logging
from pydantic import BaseModel
from google import genai
from google.genai import types
from confluent_kafka import Consumer, KafkaError, KafkaException
from dotenv import load_dotenv
import psycopg


load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('analyzer-worker')

class MitigationPlan(BaseModel):
    threat_classification: str
    affected_components: list[str]
    immediate_action_required: str
    risk_level: str

def analyze_threat(payload: dict, client: genai.Client) -> str:
    """Sends the raw threat to Gemini and asks for a structured mitigation plan."""
    prompt = f"""
    You are an expert Security Operations Center (SOC) AI.
    Analyze the following raw threat intelligence alert and provide a structured mitigation plan.
    
    Raw Alert:
    Source: {payload.get('source')}
    Severity: {payload.get('severity')}
    Description: {payload.get('description')}
    """
    
    response = client.models.generate_content(
        model='gemini-3.5-flash-lite',
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=MitigationPlan,
            temperature=0.1,
        ),
    )
    return response.text

def save_to_db(source: str, severity: str, mitigation_json: str):
    conn_info = f"host={os.environ.get('POSTGRES_HOST')} port={os.environ.get('POSTGRES_PORT')} dbname={os.environ.get('POSTGRES_DB')} user={os.environ.get('POSTGRES_USER')} password={os.environ.get('POSTGRES_PASSWORD')}"
    
    mitigation_data = json.loads(mitigation_json)
    
    with psycopg.connect(conn_info) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO threat_intelligence 
                (source, original_severity, threat_classification, affected_components, immediate_action_required, risk_level) 
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id;
            """, (
                source,
                severity,
                mitigation_data['threat_classification'],
                mitigation_data['affected_components'],
                mitigation_data['immediate_action_required'],
                mitigation_data['risk_level']
            ))
            record_id = cur.fetchone()[0]
            conn.commit()
            return record_id

def main():
    api_key = os.environ.get('GEMINI_API_KEY')
    if not api_key:
        logger.error("GEMINI_API_KEY environment variable is not set. Exiting.")
        return

    gemini_client = genai.Client(api_key=api_key)

    kafka_broker = os.environ.get('KAFKA_BROKER', 'localhost:9094')
    kafka_topic = os.environ.get('KAFKA_TOPIC', 'raw-threat-intel')
    consumer_group = os.environ.get('KAFKA_CONSUMER_GROUP', 'analyzer-worker-group')

    conf = {
        'bootstrap.servers': kafka_broker,
        'group.id': consumer_group,
        'auto.offset.reset': 'earliest',
        'enable.auto.commit': False
    }

    consumer = Consumer(conf)
    consumer.subscribe([kafka_topic])
    logger.info(f"Subscribed to topic '{kafka_topic}'. Waiting for threats...")

    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None: continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    logger.error(f"Kafka Error: {msg.error()}")
                continue

            try:
                data = json.loads(msg.value().decode('utf-8'))
                source = data.get('source')
                severity = data.get('severity')

                logger.info(f"Processing new alert from {data.get('source')}...")
                
                mitigation_json = analyze_threat(data, gemini_client)

                record_id = save_to_db(source, severity, mitigation_json)
                logger.info(f"Successfully saved AI Mitigation Plan to database (Record ID: {record_id}).")
                
                consumer.commit(asynchronous=False)
                
            except Exception as e:
                logger.error(f"Failed to process message: {e}")

    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        consumer.close()

if __name__ == '__main__':
    main()