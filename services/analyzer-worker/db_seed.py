import os
import psycopg
from dotenv import load_dotenv

load_dotenv()

def seed_inventory():
    conn_info = f"host={os.environ.get('POSTGRES_HOST')} port={os.environ.get('POSTGRES_PORT')} dbname={os.environ.get('POSTGRES_DB')} user={os.environ.get('POSTGRES_USER')} password={os.environ.get('POSTGRES_PASSWORD')}"
    
    with psycopg.connect(conn_info) as conn:
        with conn.cursor() as cur:
            print("Creating asset_inventory table...")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS asset_inventory (
                    id SERIAL PRIMARY KEY,
                    hostname VARCHAR(255) NOT NULL,
                    ip_address VARCHAR(15) NOT NULL,
                    os_type VARCHAR(50) NOT NULL,
                    primary_software VARCHAR(100) NOT NULL,
                    environment VARCHAR(50) NOT NULL,
                    status VARCHAR(50) DEFAULT 'ACTIVE'
                );
            """)
            
            print("Seeding mock servers...")
            cur.execute("TRUNCATE TABLE asset_inventory;")
            
            cur.execute("""
                INSERT INTO asset_inventory (hostname, ip_address, os_type, primary_software, environment) VALUES
                ('web-prod-01', '10.0.1.10', 'Ubuntu 22.04', 'Apache', 'production'),
                ('db-prod-01', '10.0.1.20', 'RHEL 9', 'PostgreSQL', 'production'),
                ('api-prod-01', '10.0.1.30', 'Alpine Linux', 'Go Microservice', 'production'),
                ('web-dev-01', '10.0.2.10', 'Ubuntu 22.04', 'Apache', 'development');
            """)
            conn.commit()
            print("Asset inventory seeded successfully.")

if __name__ == '__main__':
    seed_inventory()