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

CREATE TABLE IF NOT EXISTS asset_inventory (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    ip_address VARCHAR(15) NOT NULL,
    os_type VARCHAR(50) NOT NULL,
    primary_software VARCHAR(100) NOT NULL,
    environment VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'ACTIVE'
);

INSERT INTO asset_inventory (hostname, ip_address, os_type, primary_software, environment) VALUES
('web-prod-01', '10.0.1.10', 'Ubuntu 22.04', 'Apache', 'production'),
('db-prod-01', '10.0.1.20', 'RHEL 9', 'PostgreSQL', 'production'),
('api-prod-01', '10.0.1.30', 'Alpine Linux', 'Go Microservice', 'production'),
('web-dev-01', '10.0.2.10', 'Ubuntu 22.04', 'Apache', 'development')
ON CONFLICT DO NOTHING;