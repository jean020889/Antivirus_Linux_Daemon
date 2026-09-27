# core/db.py
"""Capa de acceso a PostgreSQL para el EDR."""
import os
import json
from contextlib import contextmanager

import psycopg2
from psycopg2.extras import RealDictCursor, Json


class DB:
    def __init__(self, config=None):
        config = config or {}
        self.params = {
            "host": os.environ.get('AV_DB_HOST', 'localhost'),
            "port": os.environ.get('AV_DB_PORT', '5432'),
            "dbname": os.environ.get('AV_DB_NAME', 'antivirus_pro'),
            "user": os.environ.get('AV_DB_USER', 'antivirus'),
            "password": os.environ.get('AV_DB_PASS', 'changeme'),
        }

    @contextmanager
    def cursor(self):
        conn = psycopg2.connect(**self.params, cursor_factory=RealDictCursor)
        try:
            yield conn.cursor()
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ============================================
    # ENDPOINTS
    # ============================================
    def upsert_endpoint(self, hostname, ip=None, os_name=None, os_version=None,
                        kernel=None, agent_version=None, cpu=None, ram_mb=None):
        with self.cursor() as cur:
            cur.execute("""
                INSERT INTO endpoints (hostname, ip_address, os_name, os_version,
                                       kernel_version, agent_version, cpu_model, total_ram_mb,
                                       last_seen, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), 'active')
                ON CONFLICT (hostname) DO UPDATE SET
                    ip_address = EXCLUDED.ip_address,
                    last_seen = NOW(),
                    agent_version = EXCLUDED.agent_version,
                    status = 'active'
                RETURNING id
            """, (hostname, ip, os_name, os_version, kernel, agent_version, cpu, ram_mb))
            return cur.fetchone()['id']

    def update_health_score(self, hostname, score):
        with self.cursor() as cur:
            cur.execute("UPDATE endpoints SET health_score = %s WHERE hostname = %s", (score, hostname))

    # ============================================
    # THREATS
    # ============================================
    def insert_threat(self, endpoint_id, file_path, threat_name, detection_engine,
                     detection_type, severity='medium', confidence=50,
                     md5=None, sha256=None, file_size=None,
                     quarantined=False, quarantine_path=None, mitre=None):
        with self.cursor() as cur:
            cur.execute("""
                INSERT INTO threats (endpoint_id, file_path, threat_name,
                                    detection_engine, detection_type, severity, confidence,
                                    file_hash_md5, file_hash_sha256, file_size,
                                    quarantined, quarantine_path, mitre_technique)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (endpoint_id, file_path, threat_name, detection_engine,
                  detection_type, severity, confidence, md5, sha256, file_size,
                  quarantined, quarantine_path, mitre))
            return cur.fetchone()['id']

    def list_threats(self, limit=100, severity=None, since=None):
        with self.cursor() as cur:
            q = """
                SELECT t.*, e.hostname FROM threats t
                JOIN endpoints e ON t.endpoint_id = e.id
                WHERE 1=1
            """
            params = []
            if severity:
                q += " AND t.severity = %s"
                params.append(severity)
            if since:
                q += " AND t.detected_at >= %s"
                params.append(since)
            q += " ORDER BY t.detected_at DESC LIMIT %s"
            params.append(limit)
            cur.execute(q, params)
            return cur.fetchall()

    # ============================================
    # TELEMETRY
    # ============================================
    def insert_telemetry(self, endpoint_id, event_type, event_data,
                         process_pid=None, process_name=None, process_user=None,
                         parent_pid=None, file_path=None,
                         src_ip=None, dst_ip=None, dst_port=None,
                         mitre=None, severity='info'):
        with self.cursor() as cur:
            cur.execute("""
                INSERT INTO telemetry (endpoint_id, event_type, event_data,
                                       process_pid, process_name, process_user, parent_pid,
                                       file_path, network_src_ip, network_dst_ip, network_dst_port,
                                       mitre_technique, severity)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (endpoint_id, event_type, Json(event_data),
                  process_pid, process_name, process_user, parent_pid,
                  file_path, src_ip, dst_ip, dst_port, mitre, severity))
            return cur.fetchone()['id']

    # ============================================
    # ALERTS
    # ============================================
    def insert_alert(self, endpoint_id, rule_id, rule_name, description,
                    rule_level='medium', threat_id=None, matched_event_ids=None):
        with self.cursor() as cur:
            cur.execute("""
                INSERT INTO alerts (endpoint_id, rule_id, rule_name, rule_level,
                                    description, threat_id, matched_event_ids)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (endpoint_id, rule_id, rule_name, rule_level,
                  description, threat_id, matched_event_ids or []))
            return cur.fetchone()['id']

    def update_alert_status(self, alert_id, status, notes=None, user=None):
        with self.cursor() as cur:
            if status == 'acknowledged':
                cur.execute("UPDATE alerts SET status='acknowledged', acknowledged_at=NOW() WHERE id=%s", (alert_id,))
            elif status == 'resolved':
                cur.execute("""UPDATE alerts SET status='resolved', resolved_at=NOW(),
                            resolution_notes=%s, resolver_user=%s WHERE id=%s""",
                          (notes, user, alert_id))

    # ============================================
    # CTI
    # ============================================
    def upsert_ioc(self, ioc_type, ioc_value, source, **kwargs):
        with self.cursor() as cur:
            cur.execute("""
                INSERT INTO cti_iocs (ioc_type, ioc_value, ioc_value_normalized, source,
                                     threat_type, malware_family, confidence, severity,
                                     first_seen, last_seen, tags, metadata)
                VALUES (%s, %s, LOWER(%s), %s, %s, %s, %s, %s, %s, NOW(), %s, %s)
                ON CONFLICT (ioc_type, ioc_value, source) DO UPDATE SET
                    last_seen = NOW(),
                    confidence = EXCLUDED.confidence
                RETURNING id
            """, (ioc_type, ioc_value, ioc_value, source,
                  kwargs.get('threat_type'), kwargs.get('malware_family'),
                  kwargs.get('confidence', 50), kwargs.get('severity', 'medium'),
                  kwargs.get('first_seen'), Json(kwargs.get('tags', [])),
                  Json(kwargs.get('metadata', {}))))
            return cur.fetchone()['id']

    # ============================================
    # STATS
    # ============================================
    def get_stats(self):
        with self.cursor() as cur:
            stats = {}
            cur.execute("SELECT COUNT(*) as c FROM endpoints WHERE status='active'")
            stats['endpoints'] = cur.fetchone()['c']
            cur.execute("SELECT COUNT(*) as c FROM threats")
            stats['threats_total'] = cur.fetchone()['c']
            cur.execute("SELECT COUNT(*) as c FROM threats WHERE detected_at > NOW() - INTERVAL '24 hours'")
            stats['threats_24h'] = cur.fetchone()['c']
            cur.execute("SELECT COUNT(*) as c FROM alerts WHERE status='open'")
            stats['alerts_open'] = cur.fetchone()['c']
            cur.execute("SELECT COUNT(*) as c FROM cti_iocs")
            stats['cti_iocs'] = cur.fetchone()['c']
            cur.execute("SELECT severity, COUNT(*) as c FROM threats GROUP BY severity")
            stats['by_severity'] = {r['severity']: r['c'] for r in cur.fetchall()}
            cur.execute("SELECT detection_engine, COUNT(*) as c FROM threats GROUP BY detection_engine")
            stats['by_engine'] = {r['detection_engine']: r['c'] for r in cur.fetchall()}
            return stats

    # ============================================
    # FIRMAS PROPIAS (extensión)
    # ============================================
    def upsert_custom_signature(self, sig_type, sig_value, sig_name,
                                 description=None, severity='medium',
                                 confidence=50, source='auto_learn',
                                 sample_hash=None, sample_path=None,
                                 mitre_technique=None):
        """Añade o actualiza una firma propia."""
        with self.cursor() as cur:
            cur.execute("""
                INSERT INTO custom_signatures 
                    (sig_type, sig_value, sig_name, description, severity,
                     confidence, source, sample_hash, sample_path, mitre_technique)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (sig_type, sig_value) DO UPDATE SET
                    detection_count = custom_signatures.detection_count + 1,
                    last_matched = NOW()
                RETURNING id
            """, (sig_type, sig_value, sig_name, description, severity,
                  confidence, source, sample_hash, sample_path, mitre_technique))
            return cur.fetchone()['id']

    def increment_signature_match(self, sig_type, sig_value):
        """Incrementa el contador de detecciones de una firma."""
        with self.cursor() as cur:
            cur.execute("""
                UPDATE custom_signatures 
                SET detection_count = detection_count + 1, last_matched = NOW()
                WHERE sig_type = %s AND sig_value = %s
            """, (sig_type, sig_value))

    def mark_signature_false_positive(self, sig_id, user_id=None, notes=None):
        """Marca una firma como falso positivo."""
        with self.cursor() as cur:
            cur.execute("""
                UPDATE custom_signatures 
                SET false_positive_count = false_positive_count + 1,
                    enabled = CASE 
                        WHEN false_positive_count + 1 > detection_count * 0.5 THEN FALSE
                        ELSE enabled 
                    END
                WHERE id = %s
            """, (sig_id,))
            cur.execute("""
                INSERT INTO signature_feedback (signature_id, user_id, feedback, notes)
                VALUES (%s, %s, 'false_positive', %s)
            """, (sig_id, user_id, notes))

    def get_enabled_custom_signatures(self, sig_type=None):
        """Obtiene firmas activas."""
        with self.cursor() as cur:
            q = "SELECT * FROM custom_signatures WHERE enabled = TRUE"
            params = []
            if sig_type:
                q += " AND sig_type = %s"
                params.append(sig_type)
            cur.execute(q, params)
            return cur.fetchall()

    def save_malware_sample(self, filepath, family=None, tags=None):
        """Guarda un sample de malware (metadata + ruta)."""
        import hashlib
        try:
            sha256 = hashlib.sha256(open(filepath, 'rb').read()).hexdigest()
            md5 = hashlib.md5(open(filepath, 'rb').read()).hexdigest()
            size = os.path.getsize(filepath)
        except Exception:
            return None

        with self.cursor() as cur:
            cur.execute("""
                INSERT INTO malware_samples (sha256, md5, file_size, family, tags, storage_path)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (sha256) DO UPDATE SET
                    detection_count = malware_samples.detection_count + 1,
                    last_seen = NOW()
                RETURNING id
            """, (sha256, md5, size, family, tags or [], filepath))
            return cur.fetchone()['id']

    def get_signature_stats(self):
        """Estadísticas de firmas."""
        with self.cursor() as cur:
            cur.execute("""
                SELECT sig_type, COUNT(*) as count,
                       SUM(detection_count) as detections,
                       SUM(false_positive_count) as false_positives
                FROM custom_signatures
                GROUP BY sig_type
            """)
            return cur.fetchall()
