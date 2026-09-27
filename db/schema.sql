-- Auto-cargado por PostgreSQL en el primer arranque
-- (Contenido idéntico a la FASE 1)
CREATE TABLE IF NOT EXISTS endpoints (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) UNIQUE NOT NULL,
    ip_address INET,
    mac_address VARCHAR(17),
    os_name VARCHAR(100),
    os_version VARCHAR(50),
    kernel_version VARCHAR(100),
    agent_version VARCHAR(20),
    cpu_model VARCHAR(200),
    total_ram_mb INTEGER,
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    status VARCHAR(20) DEFAULT 'active',
    health_score INTEGER DEFAULT 100,
    tags JSONB DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status);
CREATE INDEX IF NOT EXISTS idx_endpoints_last_seen ON endpoints(last_seen DESC);

CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    endpoint_id INTEGER REFERENCES endpoints(id) ON DELETE CASCADE,
    scan_type VARCHAR(50) NOT NULL,
    scan_path TEXT,
    started_at TIMESTAMP DEFAULT NOW(),
    finished_at TIMESTAMP,
    files_scanned BIGINT DEFAULT 0,
    bytes_scanned BIGINT DEFAULT 0,
    threats_found INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'running',
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS threats (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    endpoint_id INTEGER REFERENCES endpoints(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    file_hash_md5 VARCHAR(32),
    file_hash_sha256 VARCHAR(64),
    file_size BIGINT,
    threat_name VARCHAR(255),
    detection_engine VARCHAR(50),
    detection_type VARCHAR(50),
    severity VARCHAR(20) DEFAULT 'medium',
    confidence INTEGER DEFAULT 50,
    quarantined BOOLEAN DEFAULT FALSE,
    quarantine_path TEXT,
    remediated BOOLEAN DEFAULT FALSE,
    remediation_action VARCHAR(50),
    mitre_technique VARCHAR(20),
    detected_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_threats_endpoint ON threats(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_threats_detected ON threats(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_threats_sha256 ON threats(file_hash_sha256);

CREATE TABLE IF NOT EXISTS telemetry (
    id BIGSERIAL PRIMARY KEY,
    endpoint_id INTEGER REFERENCES endpoints(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    event_data JSONB NOT NULL,
    process_pid INTEGER,
    process_name VARCHAR(255),
    process_user VARCHAR(100),
    process_exe TEXT,
    process_cmdline TEXT,
    parent_pid INTEGER,
    file_path TEXT,
    network_src_ip INET,
    network_dst_ip INET,
    network_dst_port INTEGER,
    mitre_technique VARCHAR(20),
    severity VARCHAR(20) DEFAULT 'info',
    timestamp TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_telemetry_endpoint ON telemetry(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_type ON telemetry(event_type);
CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp ON telemetry(timestamp DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    endpoint_id INTEGER REFERENCES endpoints(id) ON DELETE CASCADE,
    rule_id VARCHAR(100) NOT NULL,
    rule_name VARCHAR(255) NOT NULL,
    rule_level VARCHAR(20) DEFAULT 'medium',
    description TEXT,
    matched_event_ids BIGINT[],
    threat_id INTEGER REFERENCES threats(id) ON DELETE SET NULL,
    status VARCHAR(20) DEFAULT 'open',
    acknowledged_at TIMESTAMP,
    resolved_at TIMESTAMP,
    resolver_user VARCHAR(100),
    resolution_notes TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS responses (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
    endpoint_id INTEGER REFERENCES endpoints(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL,
    target TEXT,
    action_payload JSONB,
    action_result JSONB,
    success BOOLEAN,
    executed_by VARCHAR(50) DEFAULT 'soar',
    executed_at TIMESTAMP DEFAULT NOW(),
    duration_ms INTEGER
);

CREATE TABLE IF NOT EXISTS cti_iocs (
    id SERIAL PRIMARY KEY,
    ioc_type VARCHAR(50) NOT NULL,
    ioc_value VARCHAR(500) NOT NULL,
    ioc_value_normalized VARCHAR(500),
    source VARCHAR(100) NOT NULL,
    threat_type VARCHAR(100),
    malware_family VARCHAR(100),
    confidence INTEGER DEFAULT 50,
    severity VARCHAR(20) DEFAULT 'medium',
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    expires_at TIMESTAMP,
    tags JSONB DEFAULT '[]'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    UNIQUE(ioc_type, ioc_value, source)
);

CREATE TABLE IF NOT EXISTS sigma_rules (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    level VARCHAR(20),
    status VARCHAR(20) DEFAULT 'stable',
    logsource JSONB,
    detection JSONB NOT NULL,
    tags TEXT[],
    source VARCHAR(100),
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    role VARCHAR(20) DEFAULT 'analyst',
    api_key VARCHAR(100) UNIQUE,
    active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agent_config (
    id SERIAL PRIMARY KEY,
    endpoint_id INTEGER REFERENCES endpoints(id) ON DELETE CASCADE,
    config_key VARCHAR(100) NOT NULL,
    config_value JSONB NOT NULL,
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(endpoint_id, config_key)
);

CREATE TABLE IF NOT EXISTS agent_commands (
    id SERIAL PRIMARY KEY,
    endpoint_id INTEGER REFERENCES endpoints(id) ON DELETE CASCADE,
    command VARCHAR(100) NOT NULL,
    command_args JSONB,
    status VARCHAR(20) DEFAULT 'pending',
    result JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    executed_at TIMESTAMP,
    expires_at TIMESTAMP
);

-- Usuario admin por defecto (password: admin)
INSERT INTO users (username, password_hash, email, role, api_key)
VALUES (
    'admin',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK2',
    'admin@local',
    'admin',
    'CAMBIA_ESTO_POR_UNA_API_KEY_SEGURA'
) ON CONFLICT (username) DO NOTHING;
