import os
import psycopg
from dotenv import load_dotenv
from mcp.server.mcpserver import MCPServer

load_dotenv()

mcp = MCPServer("Aegis Asset Inventory")


@mcp.tool()
def check_internal_inventory(software_name: str) -> str:
    """
    Check the internal asset inventory database for running software.
    Pass the base software name (e.g., 'Apache', 'Nginx', 'PostgreSQL').
    Returns a summary of affected internal systems or indicates none were found.
    """
    conn_info = f"host={os.environ.get('POSTGRES_HOST')} port={os.environ.get('POSTGRES_PORT')} dbname={os.environ.get('POSTGRES_DB')} user={os.environ.get('POSTGRES_USER')} password={os.environ.get('POSTGRES_PASSWORD')}"

    try:
        with psycopg.connect(conn_info) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT hostname, ip_address, environment 
                    FROM asset_inventory 
                    WHERE (primary_software ILIKE %s 
                           OR %s ILIKE ('%%' || primary_software || '%%'))
                      AND status = 'ACTIVE';
                """,
                    (f"%{software_name}%", software_name),
                )

                results = cur.fetchall()

                if not results:
                    return f"No internal servers found running {software_name}. Safe to deprioritize."

                response = f"Found {len(results)} active internal servers running {software_name}:\n"
                for row in results:
                    response += f"- Host: {row[0]}, IP: {row[1]}, Env: {row[2]}\n"
                return response

    except Exception as e:
        return f"Error querying database: {str(e)}"


@mcp.tool()
def generate_firewall_rule(ip_address: str) -> str:
    """
    Generate the required iptables command to isolate a compromised internal server.
    Pass the exact IP address that needs to be quarantined.
    """
    # In a fully automated SOC, this tool would connect via SSH and execute the rule.
    # For our Aegis platform, we generate the command for the AI to include in its plan.
    rule = f"sudo iptables -A INPUT -s {ip_address} -j DROP\nsudo iptables -A OUTPUT -d {ip_address} -j DROP"
    return f"Firewall isolation script generated successfully:\n{rule}"


if __name__ == "__main__":
    mcp.run()
