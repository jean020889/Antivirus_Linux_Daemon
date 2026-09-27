# core/cluster.py
"""
Escalabilidad empresarial: clustering, balanceo, HA.

Permite:
- Múltiples nodos worker
- Distribución de tareas de escaneo
- Heartbeat entre nodos
- Failover automático
- Cola de trabajos distribuida (PostgreSQL-based)
"""
import os
import time
import socket
import threading
import json
from datetime import datetime


class ClusterManager:
    def __init__(self, db, config=None):
        self.db = db
        self.config = config or {}
        self.node_id = self.config.get('node_id', socket.gethostname())
        self.node_role = self.config.get('node_role', 'worker')  # 'master' o 'worker'
        self.running = False

    def register_node(self):
        """Registra este nodo en el cluster."""
        with self.db.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cluster_nodes (
                    id SERIAL PRIMARY KEY,
                    node_id VARCHAR(255) UNIQUE NOT NULL,
                    hostname VARCHAR(255),
                    ip_address INET,
                    role VARCHAR(20) DEFAULT 'worker',
                    status VARCHAR(20) DEFAULT 'active',
                    version VARCHAR(20),
                    cpu_cores INTEGER,
                    ram_mb INTEGER,
                    last_heartbeat TIMESTAMP DEFAULT NOW(),
                    metadata JSONB DEFAULT '{}'::jsonb
                )
            """)
            cur.execute("""
                INSERT INTO cluster_nodes (node_id, hostname, role, status, last_heartbeat)
                VALUES (%s, %s, %s, 'active', NOW())
                ON CONFLICT (node_id) DO UPDATE SET
                    last_heartbeat = NOW(),
                    status = 'active'
                RETURNING id
            """, (self.node_id, socket.gethostname(), self.node_role))
            return cur.fetchone()['id']

    def heartbeat(self):
        """Envía heartbeat."""
        try:
            self.register_node()
        except Exception:
            pass

    def get_active_nodes(self):
        """Nodos activos (último heartbeat < 60s)."""
        with self.db.cursor() as cur:
            cur.execute("""
                SELECT node_id, hostname, role, last_heartbeat
                FROM cluster_nodes
                WHERE last_heartbeat > NOW() - INTERVAL '60 seconds'
            """)
            return cur.fetchall()

    def submit_job(self, job_type, payload, priority=5):
        """Envía un trabajo a la cola distribuida."""
        with self.db.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cluster_jobs (
                    id BIGSERIAL PRIMARY KEY,
                    job_type VARCHAR(50) NOT NULL,
                    payload JSONB NOT NULL,
                    priority INTEGER DEFAULT 5,
                    status VARCHAR(20) DEFAULT 'pending',
                    assigned_node VARCHAR(255),
                    created_at TIMESTAMP DEFAULT NOW(),
                    started_at TIMESTAMP,
                    finished_at TIMESTAMP,
                    result JSONB,
                    error TEXT
                )
            """)
            cur.execute("""
                INSERT INTO cluster_jobs (job_type, payload, priority, status)
                VALUES (%s, %s, %s, 'pending')
                RETURNING id
            """, (job_type, json.dumps(payload), priority))
            return cur.fetchone()['id']

    def claim_job(self):
        """Reclama el siguiente trabajo pendiente (worker)."""
        with self.db.cursor() as cur:
            cur.execute("""
                UPDATE cluster_jobs
                SET status = 'running',
                    assigned_node = %s,
                    started_at = NOW()
                WHERE id = (
                    SELECT id FROM cluster_jobs
                    WHERE status = 'pending'
                    ORDER BY priority ASC, created_at ASC
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING id, job_type, payload
            """, (self.node_id,))
            row = cur.fetchone()
            if row:
                return {
                    'id': row['id'],
                    'job_type': row['job_type'],
                    'payload': row['payload'],
                }
        return None

    def complete_job(self, job_id, result=None, error=None):
        """Marca un trabajo como completado."""
        with self.db.cursor() as cur:
            cur.execute("""
                UPDATE cluster_jobs
                SET status = %s,
                    finished_at = NOW(),
                    result = %s,
                    error = %s
                WHERE id = %s
            """, (
                'completed' if not error else 'failed',
                json.dumps(result) if result else None,
                error,
                job_id
            ))

    def start_heartbeat_loop(self):
        """Inicia loop de heartbeat."""
        self.running = True
        def loop():
            while self.running:
                try:
                    self.heartbeat()
                except Exception:
                    pass
                time.sleep(30)
        threading.Thread(target=loop, daemon=True).start()

    def start_worker_loop(self, job_handlers):
        """
        Loop de worker que procesa jobs.
        job_handlers: dict {job_type: callable(payload) -> result}
        """
        self.running = True
        def loop():
            while self.running:
                try:
                    job = self.claim_job()
                    if job:
                        handler = job_handlers.get(job['job_type'])
                        if handler:
                            try:
                                result = handler(job['payload'])
                                self.complete_job(job['id'], result=result)
                            except Exception as e:
                                self.complete_job(job['id'], error=str(e))
                        else:
                            self.complete_job(job['id'], error=f"No handler for {job['job_type']}")
                    else:
                        time.sleep(5)
                except Exception:
                    time.sleep(5)
        threading.Thread(target=loop, daemon=True).start()

    def stop(self):
        self.running = False
