# web/dashboard.py
"""
Dashboard web para monitorizar el estado del Antivirus Pro.
Ejecutar con: uvicorn web.dashboard:app --host 0.0.0.0 --port 8080
"""

from fastapi import FastAPI, WebSocket, HTTPException, Header
from fastapi.responses import HTMLResponse
import json
import os
import asyncio
from datetime import datetime

app = FastAPI(title="Antivirus Pro Dashboard")

# Ruta del archivo de estado (compartido con el daemon)
STATE_FILE = "/var/lib/antivirus-pro/state.json"
API_TOKEN = os.environ.get("AV_API_TOKEN")
if not API_TOKEN:
    raise RuntimeError(
        "AV_API_TOKEN obligatorio. Configúralo en .env "
        "(genera con: python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
    )
if API_TOKEN.startswith("CAMBIA"):
    raise RuntimeError("AV_API_TOKEN tiene el placeholder por defecto. Cámbialo en .env")


def load_state():
    """Carga el estado actual del antivirus desde el archivo compartido."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {
        "status": "unknown",
        "last_scan": None,
        "threats": 0,
        "signatures": 0,
        "events": []
    }


def save_state(state):
    """Guarda el estado actual."""
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)


INDEX_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🛡️ Antivirus Pro - Dashboard</title>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    color: #e2e8f0; margin: 0; padding: 2rem; min-height: 100vh;
  }
  h1 { color: #38bdf8; margin-bottom: 0.5rem; }
  .subtitle { color: #94a3b8; margin-bottom: 2rem; }
  .grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 1rem; margin-bottom: 2rem;
  }
  .card {
    background: rgba(30, 41, 59, 0.8); border: 1px solid #334155;
    border-radius: 12px; padding: 1.5rem;
    backdrop-filter: blur(10px); transition: transform 0.2s;
  }
  .card:hover { transform: translateY(-2px); border-color: #38bdf8; }
  .card .label { font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; }
  .metric { font-size: 2.2rem; font-weight: bold; margin-top: 0.5rem; }
  .status-ok { color: #4ade80; }
  .status-warn { color: #fbbf24; }
  .status-bad { color: #f87171; }
  .events-card { background: rgba(30, 41, 59, 0.8); border: 1px solid #334155; border-radius: 12px; padding: 1.5rem; }
  .events-card h2 { color: #38bdf8; margin-top: 0; }
  #events { list-style: none; padding: 0; max-height: 400px; overflow-y: auto; }
  #events li { padding: 0.5rem; border-bottom: 1px solid #334155; font-family: monospace; font-size: 0.9rem; }
  #events li:last-child { border-bottom: none; }
  .dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 8px; }
  .dot.ok { background: #4ade80; animation: pulse 2s infinite; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
</style>
</head>
<body>
<h1>🛡️ Antivirus Pro Dashboard</h1>
<p class="subtitle">Monitorización en tiempo real del estado del sistema</p>

<div class="grid">
  <div class="card">
    <div class="label">Estado</div>
    <div id="status" class="metric status-ok">
      <span class="dot ok"></span><span id="status-text">--</span>
    </div>
  </div>
  <div class="card">
    <div class="label">Amenazas Detectadas</div>
    <div id="threats" class="metric status-bad">--</div>
  </div>
  <div class="card">
    <div class="label">Último Escaneo</div>
    <div id="last_scan" class="metric" style="font-size: 1.1rem;">--</div>
  </div>
  <div class="card">
    <div class="label">Firmas Cargadas</div>
    <div id="signatures" class="metric">--</div>
  </div>
</div>

<div class="events-card">
  <h2>📋 Actividad Reciente</h2>
  <ul id="events"><li>Esperando datos...</li></ul>
</div>

<script>
const ws = new WebSocket(`ws://${location.host}/ws`);

ws.onmessage = (e) => {
  try {
    const d = JSON.parse(e.data);
    document.getElementById('status-text').textContent = d.status || 'unknown';
    document.getElementById('threats').textContent = d.threats || 0;
    document.getElementById('last_scan').textContent = d.last_scan || 'Nunca';
    document.getElementById('signatures').textContent = (d.signatures || 0).toLocaleString();

    const eventsEl = document.getElementById('events');
    if (d.events && d.events.length > 0) {
      eventsEl.innerHTML = d.events.slice(-50).reverse().map(x =>
        `<li>[${x.time || ''}] ${x.message || ''}</li>`
      ).join('');
    }
  } catch (err) { console.error('Error parseando WS:', err); }
};

ws.onerror = () => {
  document.getElementById('events').innerHTML = '<li>⚠️ Error de conexión WebSocket</li>';
};

ws.onclose = () => {
  document.getElementById('events').innerHTML = '<li>🔌 Conexión cerrada. Recargando...</li>';
  setTimeout(() => location.reload(), 3000);
};
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def index():
    """Sirve el dashboard HTML."""
    return INDEX_HTML


@app.get("/api/state")
async def api_state(authorization: str = Header(None)):
    """Endpoint REST para obtener el estado (requiere token)."""
    if authorization != f"Bearer {API_TOKEN}":
        raise HTTPException(status_code=401, detail="No autorizado")
    return load_state()


@app.post("/api/scan")
async def api_scan(path: str = "/home", authorization: str = Header(None)):
    """Dispara un escaneo (requiere token)."""
    if authorization != f"Bearer {API_TOKEN}":
        raise HTTPException(status_code=401, detail="No autorizado")
    # En producción, esto se comunicaría con el daemon vía socket Unix
    return {"status": "started", "path": path, "timestamp": datetime.now().isoformat()}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket para actualizaciones en tiempo real."""
    await websocket.accept()
    try:
        while True:
            state = load_state()
            await websocket.send_text(json.dumps(state))
            await asyncio.sleep(2)
    except Exception:
        pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
