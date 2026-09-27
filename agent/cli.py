# agent/cli.py
"""CLI para gestionar agentes desde el servidor central."""
import sys
import argparse
import requests
import os


class EDRCLI:
    def __init__(self, server_url=None, api_key=None):
        self.server_url = server_url or os.environ.get('AV_SERVER', 'http://localhost:8002')
        self.api_key = api_key or os.environ.get('AV_API_KEY', 'test_key')
        self.headers = {'Authorization': f'Bearer {self.api_key}'}

    def list_endpoints(self):
        r = requests.get(f"{self.server_url}/api/endpoints", headers=self.headers, timeout=10)
        if r.status_code == 200:
            for e in r.json():
                print(f"  [{e['id']}] {e['hostname']} ({e.get('ip_address', '-')}) "
                      f"- {e.get('status')} - health: {e.get('health_score', 0)}%")
        else:
            print(f"Error: {r.status_code}")

    def list_threats(self, limit=50):
        r = requests.get(f"{self.server_url}/api/threats?limit={limit}",
                        headers=self.headers, timeout=10)
        if r.status_code == 200:
            for t in r.json():
                print(f"  [{t['id']}] {t.get('hostname')} - {t.get('threat_name')} "
                      f"- {t.get('severity')} - {t.get('detected_at')}")
        else:
            print(f"Error: {r.status_code}")

    def send_command(self, hostname, command, args=None):
        """Envía un comando a un agente vía API."""
        import psycopg2
        try:
            conn = psycopg2.connect(
                host=os.environ.get('AV_DB_HOST', 'localhost'),
                port=os.environ.get('AV_DB_PORT', '5432'),
                database=os.environ.get('AV_DB_NAME', 'antivirus_pro'),
                user=os.environ.get('AV_DB_USER', 'antivirus'),
                password=os.environ.get('AV_DB_PASS', 'changeme')
            )
            cur = conn.cursor()
            cur.execute("SELECT id FROM endpoints WHERE hostname = %s", (hostname,))
            row = cur.fetchone()
            if not row:
                print(f"❌ Endpoint no encontrado: {hostname}")
                return
            endpoint_id = row[0]

            import json
            cur.execute("""
                INSERT INTO agent_commands (endpoint_id, command, command_args, status)
                VALUES (%s, %s, %s, 'pending')
                RETURNING id
            """, (endpoint_id, command, json.dumps(args or {})))
            cmd_id = cur.fetchone()[0]
            conn.commit()
            conn.close()
            print(f"✅ Comando enviado (id={cmd_id}): {command} -> {hostname}")
        except Exception as e:
            print(f"❌ Error: {e}")

    def stats(self):
        r = requests.get(f"{self.server_url}/api/stats", headers=self.headers, timeout=10)
        if r.status_code == 200:
            import json
            print(json.dumps(r.json(), indent=2))
        else:
            print(f"Error: {r.status_code}")


def main():
    parser = argparse.ArgumentParser(description="EDR CLI")
    sub = parser.add_subparsers(dest='cmd')

    sub.add_parser('endpoints', help='Listar endpoints')
    p_threats = sub.add_parser('threats', help='Listar amenazas')
    p_threats.add_argument('--limit', type=int, default=50)

    sub.add_parser('stats', help='Estadísticas globales')

    p_cmd = sub.add_parser('send', help='Enviar comando a endpoint')
    p_cmd.add_argument('hostname')
    p_cmd.add_argument('command',
                       choices=['scan_now', 'kill_process', 'quarantine_file',
                                'block_ip', 'collect_forensics'])
    p_cmd.add_argument('--args', default='{}', help='JSON args')

    args = parser.parse_args()
    cli = EDRCLI()

    if args.cmd == 'endpoints':
        cli.list_endpoints()
    elif args.cmd == 'threats':
        cli.list_threats(args.limit)
    elif args.cmd == 'stats':
        cli.stats()
    elif args.cmd == 'send':
        import json
        cli.send_command(args.hostname, args.command, json.loads(args.args))
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
