import os
import psycopg
from dotenv import load_dotenv

load_dotenv()

def init_db():
    conn_info = f"""
        host={os.environ.get('POSTGRES_HOST')} 
        port={os.environ.get('POSTGRES_PORT')} 
        dbname={os.environ.get('POSTGRES_DB')} 
        user={os.environ.get('POSTGRES_USER')} 
        password={os.environ.get('POSTGRES_PASSWORD')}
    """
    
    with psycopg.connect(conn_info) as conn:
        with conn.cursor() as cur:
            print("Creating threat_intelligence table...")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id SERIAL PRIMARY KEY,
                    source VARCHAR(255) NOT NULL,
                    original_severity VARCHAR(50) NOT NULL,
                    threat_classification VARCHAR(255) NOT NULL,
                    affected_components TEXT[] NOT NULL,
                    immediate_action_required TEXT NOT NULL,
                    risk_level VARCHAR(50) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()
            print("Database initialized successfully.")

if __name__ == '__main__':
    init_db()