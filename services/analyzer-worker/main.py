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

# NEW: MCP Client Imports
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('analyzer-worker')

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
            cur.execute("""
                INSERT INTO threat_intelligence 
                (source, original_severity, threat_classification, affected_components, immediate_action_required, risk_level) 
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id;
            """, (
                source, severity, mitigation_data['threat_classification'],
                mitigation_data['affected_components'], mitigation_data['immediate_action_required'],
                mitigation_data['risk_level']
            ))
            conn.commit()
            return cur.fetchone()[0]

# NEW: The Autonomous Agent Logic
async def analyze_with_mcp(payload: dict, client: genai.Client) -> str:
    # 1. Define the MCP Server connection (runs mcp_server.py as a subprocess)
    server_params = StdioServerParameters(
        command="python",
        args=["mcp_server.py"],
        env=os.environ.copy()
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # 2. Define the tool for Gemini
            inventory_tool = types.Tool(
                function_declarations=[
                    types.FunctionDeclaration(
                        name="check_internal_inventory",
                        description="Check if we run specific software (e.g., Apache, Nginx). Always use this to verify affected systems.",
                        parameters=types.Schema(
                            type=types.Type.OBJECT,
                            properties={"software_name": types.Schema(type=types.Type.STRING)},
                            required=["software_name"]
                        )
                    )
                ]
            )

            prompt = f"""
            You are an expert SOC AI. Analyze this threat:
            Source: {payload.get('source')}
            Severity: {payload.get('severity')}
            Description: {payload.get('description')}
            
            CRITICAL INSTRUCTION: You MUST use the check_internal_inventory tool to see if we actually run the targeted software before deciding the risk level. If the tool indicates we DO NOT run the software, you must assess the risk_level as 'LOW' and note that no immediate action is required.
            """

            logger.info("Requesting initial analysis from Gemini...")
            
            # 3. Call Gemini (giving it access to the tool, but NOT forcing JSON yet)
            response = client.models.generate_content(
                model='gemini-3.5-flash-lite',
                contents=prompt,
                config=types.GenerateContentConfig(tools=[inventory_tool], temperature=0.1)
            )

            # 4. Check if Gemini decided to use the tool
            if response.function_calls:
                for function_call in response.function_calls:
                    if function_call.name == "check_internal_inventory":
                        software = function_call.args["software_name"]
                        logger.info(f"[*] AI Agent initiated Tool Call: Checking inventory for '{software}'...")
                        
                        # Forward the request to our local MCP Server
                        mcp_result = await session.call_tool(
                            "check_internal_inventory", 
                            arguments={"software_name": software}
                        )
                        tool_output = mcp_result.content[0].text
                        logger.info(f"[*] MCP Server replied: {tool_output.strip()}")
                        
                        # 5. Send the database results back to Gemini and enforce JSON structure
                        logger.info("Sending database results back to Gemini for final verdict...")
                        final_response = client.models.generate_content(
                            model='gemini-3.5-flash-lite',
                            contents=[
                                prompt,
                                response.candidates[0].content,
                                types.Content(
                                    role="user",
                                    parts=[types.Part.from_function_response(
                                        name="check_internal_inventory",
                                        response={"result": tool_output}
                                    )]
                                )
                            ],
                            config=types.GenerateContentConfig(
                                response_mime_type="application/json",
                                response_schema=MitigationPlan,
                                temperature=0.1,
                            )
                        )
                        return final_response.text

            # Fallback if Gemini somehow didn't use the tool (rare with explicit prompts)
            logger.warning("Gemini bypassed the tool. Generating JSON fallback...")
            fallback = client.models.generate_content(
                model='gemini-3.5-flash-lite', contents=prompt,
                config=types.GenerateContentConfig(response_mime_type="application/json", response_schema=MitigationPlan, temperature=0.1)
            )
            return fallback.text

def main():
    api_key = os.environ.get('GEMINI_API_KEY')
    if not api_key: return logger.error("GEMINI_API_KEY is missing.")

    gemini_client = genai.Client(api_key=api_key)
    conf = {
        'bootstrap.servers': os.environ.get('KAFKA_BROKER', 'localhost:9094'),
        'group.id': os.environ.get('KAFKA_CONSUMER_GROUP', 'analyzer-worker-group'),
        'auto.offset.reset': 'earliest',
        'enable.auto.commit': False
    }

    consumer = Consumer(conf)
    consumer.subscribe([os.environ.get('KAFKA_TOPIC', 'raw-threat-intel')])
    logger.info("Subscribed to Kafka. Agent online.")

    try:
        while True:
            msg = consumer.poll(timeout=1.0)
            if msg is None: continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF: logger.error(f"Kafka Error: {msg.error()}")
                continue

            try:
                data = json.loads(msg.value().decode('utf-8'))
                logger.info(f"\n--- New Alert: {data.get('source')} ---")
                
                # Execute the async MCP function inside our synchronous consumer loop
                mitigation_json = asyncio.run(analyze_with_mcp(data, gemini_client))
                
                logger.info(f"Final AI Plan:\n{json.dumps(json.loads(mitigation_json), indent=2)}")
                record_id = save_to_db(data.get('source'), data.get('severity'), mitigation_json)
                logger.info(f"Database Record Created: ID {record_id}")
                
                consumer.commit(asynchronous=False)
                
            except Exception as e:
                logger.error(f"Failed to process message: {e}")

    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        consumer.close()

if __name__ == '__main__':
    main()