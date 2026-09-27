#!/bin/bash
set -e

case "$1" in
    daemon)
        echo "🛡️  Iniciando Antivirus Pro EDR (daemon)..."
        exec python3 /app/antivirus.py --daemon --config /app/config.json
        ;;
    api)
        echo "🌐 Iniciando API central..."
        exec uvicorn server.api:app --host 0.0.0.0 --port 8003
        ;;
    dashboard)
        echo "📊 Iniciando dashboard web..."
        exec uvicorn web.dashboard:app --host 0.0.0.0 --port 8081
        ;;
    agent)
        echo "🤖 Iniciando agente EDR..."
        exec python3 /app/agent/edr_agent.py /app/agent_config.json
        ;;
    scan)
        echo "🔍 Ejecutando escaneo..."
        exec python3 /app/antivirus.py --scan "${2:-/tmp}"
        ;;
    shell)
        exec /bin/bash
        ;;
    *)
        echo "Uso: $0 {daemon|api|dashboard|agent|scan|shell}"
        exit 1
        ;;
esac
