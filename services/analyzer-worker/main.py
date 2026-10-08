import os
import json
import logging
import psycopg
import asyncio
from dotenv import load_dotenv
from pydantic import BaseModel
from google import genai
from google.genai import types
from confluent_kafka import Consumer, KafkaError, KafkaException

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from tenacity import retry, stop_after_attempt, wait_exponential

load_dotenv()

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("analyzer-worker")


class MitigationPlan(BaseModel):
    threat_classification: str
    affected_components: list[str]
    immediate_action_required: str
    risk_level: str


def save_to_db(source: str, severity: str, mitigation_json: str):
    conn_info = f"host={os.environ.get('POSTGRES_HOST')} port={os.environ.get('POSTGRES_PORT')} dbname={os.environ.get('POSTGRES_DB')} user={os.environ.get('POSTGRES_USER')} password={os.environ.get('POSTGRES_PASSWORD')}"
    mitigation_data = json.loads(mitigation_json)

    with psycopg.connect(conn_info) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO threat_intelligence 
                (source, original_severity, threat_classification, affected_components, immediate_action_required, risk_level) 
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id;
            """,
                (
                    source,
                    severity,
                    mitigation_data["threat_classification"],
                    mitigation_data["affected_components"],
                    mitigation_data["immediate_action_required"],
                    mitigation_data["risk_level"],
                ),
            )
            conn.commit()
            return cur.fetchone()[0]


@retry(
    stop=stop_after_attempt(6),
    wait=wait_exponential(multiplier=3, min=4, max=60),
    reraise=True,
)
async def analyze_with_mcp(payload: dict, client: genai.Client) -> str:
    server_params = StdioServerParameters(
        command="python", args=["mcp_server.py"], env=os.environ.copy()
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            aegis_tools = types.Tool(
                function_declarations=[
                    types.FunctionDeclaration(
                        name="check_internal_inventory",
                        description="Check if we run specific software (e.g., Apache, Nginx).",
                        parameters=types.Schema(
                            type=types.Type.OBJECT,
                            properties={
                                "software_name": types.Schema(type=types.Type.STRING)
                            },
                            required=["software_name"],
                        ),
                    ),
                    types.FunctionDeclaration(
                        name="generate_firewall_rule",
                        description="Generate an iptables script to isolate a vulnerable internal IP.",
                        parameters=types.Schema(
                            type=types.Type.OBJECT,
                            properties={
                                "ip_address": types.Schema(type=types.Type.STRING)
                            },
                            required=["ip_address"],
                        ),
                    ),
                ]
            )

            prompt = f"""
            You are an expert SOC AI. Analyze this threat:
            Source: {payload.get('source')}
            Severity: {payload.get('severity')}
            Description: {payload.get('description')}
            
            CRITICAL INSTRUCTIONS: 
            1. Use check_internal_inventory first to see if we run the targeted software.
            2. If internal servers ARE found, you MUST use generate_firewall_rule for EACH affected IP address.
            3. Once you have the rules, set risk_level to 'CRITICAL' and paste the exact firewall scripts into the immediate_action_required field of your JSON report.
            4. If no servers are found, set risk_level to 'LOW'.
            """

            history = [
                types.Content(role="user", parts=[types.Part.from_text(text=prompt)])
            ]

            logger.info("Starting autonomous agent loop...")
            findings = []

            for _ in range(3):
                response = client.models.generate_content(
                    model="gemini-3.5-flash-lite",
                    contents=history,
                    config=types.GenerateContentConfig(
                        tools=[aegis_tools], temperature=0.1
                    ),
                )

                history.append(response.candidates[0].content)

                if not response.function_calls:
                    logger.info(
                        "Agent has gathered all necessary context. Breaking loop."
                    )
                    break

                tool_responses = []
                for function_call in response.function_calls:
                    name = function_call.name
                    args = function_call.args
                    logger.info(f"[*] Agent action: {name} -> {args}")

                    mcp_result = await session.call_tool(name, arguments=args)
                    tool_output = mcp_result.content[0].text
                    logger.info(f"[*] MCP Server replied: {tool_output.strip()}")

                    findings.append(tool_output.strip())

                    tool_responses.append(
                        types.Part.from_function_response(
                            name=name, response={"result": tool_output}
                        )
                    )

                history.append(types.Content(role="user", parts=tool_responses))

            logger.info("Generating final JSON Mitigation Plan...")
            
            final_prompt = prompt + "\n\n--- INVESTIGATION RESULTS ---\n" + "\n".join(findings)
            
            final_response = client.models.generate_content(
                model="gemini-3.5-flash-lite",
                contents=final_prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=MitigationPlan,
                    temperature=0.1,
                ),
            )
            return final_response.text


def main():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return logger.error("GEMINI_API_KEY is missing.")

    gemini_client = genai.Client(api_key=api_key)
    conf = {
        "bootstrap.servers": os.environ.get("KAFKA_BROKER", "localhost:9094"),
        "group.id": os.environ.get("KAFKA_CONSUMER_GROUP", "analyzer-worker-group"),
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
    }

    consumer = Consumer(conf)
    consumer.subscribe([os.environ.get("KAFKA_TOPIC", "raw-threat-intel")])
    logger.info("Agent on")

    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    logger.error(f"Kafka Error: {msg.error()}")
                continue

            try:
                data = json.loads(msg.value().decode("utf-8"))
                logger.info(f"\n--- New Alert: {data.get('source')} ---")

                mitigation_json = asyncio.run(analyze_with_mcp(data, gemini_client))

                logger.info(
                    f"Final AI Plan:\n{json.dumps(json.loads(mitigation_json), indent=2)}"
                )
                record_id = save_to_db(
                    data.get("source"), data.get("severity"), mitigation_json
                )
                logger.info(f"Database Record Created: ID {record_id}")

                consumer.commit(asynchronous=False)

            except Exception as e:
                logger.exception("Failed to process message:")

    except KeyboardInterrupt:
        logger.info("Process interrupted")
    finally:
        consumer.close()


if __name__ == "__main__":
    main()
