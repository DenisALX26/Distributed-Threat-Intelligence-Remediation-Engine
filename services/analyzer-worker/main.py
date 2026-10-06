import os
import json
import logging
from pydantic import BaseModel
from google import genai
from google.genai import types
from confluent_kafka import Consumer, KafkaError, KafkaException
from dotenv import load_dotenv


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
                logger.info(f"Processing new alert from {data.get('source')}...")
                
                mitigation_json = analyze_threat(data, gemini_client)
                
                logger.info(f"AI Mitigation Plan Generated:\n{mitigation_json}")
                
                consumer.commit(asynchronous=False)
                
            except Exception as e:
                logger.error(f"Failed to process message: {e}")

    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        consumer.close()

if __name__ == '__main__':
    main()