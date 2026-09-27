# server/api_extended.py
"""Endpoints adicionales para agentes EDR."""
from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
import os

router = APIRouter(prefix="/api", tags=["agents"])

API_KEY = os.environ.get("AV_API_KEY", "test_key")


def verify_key(authorization: str = Header(None)):
    if authorization != f"Bearer {API_KEY}":
        raise HTTPException(status_code=401, detail="API key inválida")
    return True


class TelemetryBatch(BaseModel):
    hostname: str
    events: List[Dict[str, Any]]


class CommandResult(BaseModel):
    command_id: int
    success: bool
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


@router.post("/telemetry/report", dependencies=[Depends(verify_key)])
async def report_telemetry(batch: TelemetryBatch):
    """Recibe batch de telemetría de un agente."""
    try:
        from core.db import DB
        db = DB()

        # Buscar endpoint_id
        with db.cursor() as cur:
            cur.execute("SELECT id FROM endpoints WHERE hostname = %s", (batch.hostname,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Endpoint no registrado")
            endpoint_id = row['id']

            # Insertar eventos en batch
            for ev in batch.events:
                cur.execute("""
                    INSERT INTO telemetry (endpoint_id, event_type, event_data,
                                          process_pid, process_name, process_user,
                                          process_exe, process_cmdline, timestamp)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                """, (
                    endpoint_id,
                    ev.get('event_type', 'unknown'),
                    ev,
                    ev.get('process_pid'),
                    ev.get('process_name'),
                    ev.get('process_user'),
                    ev.get('process_exe'),
                    ev.get('process_cmdline'),
                ))

        return {"status": "ok", "events_received": len(batch.events)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/commands/pending", dependencies=[Depends(verify_key)])
async def get_pending_commands(hostname: str):
    """Devuelve comandos pendientes para un endpoint."""
    try:
        from core.db import DB
        db = DB()
        with db.cursor() as cur:
            cur.execute("""
                SELECT c.id, c.command, c.command_args, c.created_at
                FROM agent_commands c
                JOIN endpoints e ON c.endpoint_id = e.id
                WHERE e.hostname = %s
                  AND c.status = 'pending'
                  AND (c.expires_at IS NULL OR c.expires_at > NOW())
                ORDER BY c.created_at ASC
                LIMIT 10
            """, (hostname,))
            commands = cur.fetchall()

            # Marcar como enviados
            for cmd in commands:
                cur.execute("UPDATE agent_commands SET status='sent' WHERE id=%s", (cmd['id'],))

        return {"commands": [dict(c) for c in commands]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/commands/{command_id}/result", dependencies=[Depends(verify_key)])
async def report_command_result(command_id: int, result: CommandResult):
    """Reporta el resultado de un comando."""
    try:
        from core.db import DB
        from psycopg2.extras import Json
        db = DB()
        with db.cursor() as cur:
            cur.execute("""
                UPDATE agent_commands
                SET status = %s, result = %s, executed_at = NOW()
                WHERE id = %s
            """, (
                'completed' if result.success else 'failed',
                Json({
                    "success": result.success,
                    "output": result.output,
                    "error": result.error,
                }),
                command_id
            ))
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health", dependencies=[Depends(verify_key)])
async def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}
