# core/zero_trust.py
"""
Zero Trust: score de salud del endpoint.
Calcula un score 0-100 basado en:
- Actualización de firmas
- Servicios activos
- Vulnerabilidades detectadas
- Configuración de seguridad
- Historial de incidentes
"""
import os
import subprocess
import psutil
from datetime import datetime, timedelta


class ZeroTrustScorer:
    def __init__(self, config):
        self.config = config

    def compute_score(self, endpoint_data=None):
        """Calcula el score de salud 0-100."""
        score = 100
        findings = []

        # 1. Actualización de firmas ClamAV
        try:
            db_age_days = self._clamav_db_age()
            if db_age_days > 7:
                score -= 20
                findings.append({"issue": "Firmas ClamAV desactualizadas", "age_days": db_age_days, "impact": -20})
            elif db_age_days > 2:
                score -= 5
                findings.append({"issue": "Firmas ClamAV algo antiguas", "age_days": db_age_days, "impact": -5})
        except Exception:
            score -= 10
            findings.append({"issue": "No se pudo verificar firmas ClamAV", "impact": -10})

        # 2. Servicios críticos activos
        critical_services = ['antivirus-pro', 'clamav-daemon', 'clamav-freshclam']
        for svc in critical_services:
            try:
                r = subprocess.run(['systemctl', 'is-active', f'{svc}.service'],
                                 capture_output=True, text=True, timeout=5)
                if r.stdout.strip() != 'active':
                    score -= 10
                    findings.append({"issue": f"Servicio {svc} no activo", "impact": -10})
            except Exception:
                pass

        # 3. Actualizaciones del sistema pendientes
        try:
            r = subprocess.run(['apt', 'list', '--upgradable'],
                             capture_output=True, text=True, timeout=30)
            upgradable = len([l for l in r.stdout.splitlines() if '/' in l])
            if upgradable > 50:
                score -= 15
                findings.append({"issue": f"{upgradable} paquetes desactualizados", "impact": -15})
            elif upgradable > 10:
                score -= 5
                findings.append({"issue": f"{upgradable} paquetes desactualizados", "impact": -5})
        except Exception:
            pass

        # 4. Uso de disco
        try:
            disk = psutil.disk_usage('/')
            if disk.percent > 95:
                score -= 10
                findings.append({"issue": f"Disco casi lleno ({disk.percent}%)", "impact": -10})
            elif disk.percent > 85:
                score -= 3
                findings.append({"issue": f"Disco con poco espacio ({disk.percent}%)", "impact": -3})
        except Exception:
            pass

        # 5. Firewall activo
        try:
            r = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=5)
            if 'Status: active' not in r.stdout:
                score -= 10
                findings.append({"issue": "Firewall (ufw) inactivo", "impact": -10})
        except FileNotFoundError:
            pass
        except Exception:
            pass

        # 6. SSH con root login permitido
        try:
            if os.path.exists('/etc/ssh/sshd_config'):
                with open('/etc/ssh/sshd_config') as f:
                    for line in f:
                        if line.strip().startswith('PermitRootLogin yes'):
                            score -= 15
                            findings.append({"issue": "SSH permite login root", "impact": -15})
                            break
        except Exception:
            pass

        # 7. Cuarentena con archivos maliciosos recientes
        try:
            q_dir = self.config.get('cuarentena', '/opt/antivirus_cuarentena')
            if os.path.exists(q_dir):
                recent = 0
                cutoff = datetime.now() - timedelta(hours=24)
                for f in os.listdir(q_dir):
                    p = os.path.join(q_dir, f)
                    if os.path.getmtime(p) > cutoff.timestamp():
                        recent += 1
                if recent > 0:
                    score -= min(recent * 2, 15)
                    findings.append({"issue": f"{recent} amenazas en cuarentena últimas 24h", "impact": -min(recent * 2, 15)})
        except Exception:
            pass

        score = max(0, min(100, score))

        # Clasificación
        if score >= 90:
            grade = "A"
            status = "healthy"
        elif score >= 75:
            grade = "B"
            status = "good"
        elif score >= 60:
            grade = "C"
            status = "warning"
        elif score >= 40:
            grade = "D"
            status = "at_risk"
        else:
            grade = "F"
            status = "critical"

        return {
            "score": score,
            "grade": grade,
            "status": status,
            "findings": findings,
            "computed_at": datetime.now().isoformat()
        }

    def _clamav_db_age(self):
        """Verifica la antigüedad de las firmas ClamAV."""
        paths = [
            "/var/lib/clamav/daily.cld",
            "/var/lib/clamav/daily.cvd",
            "/var/lib/clamav/main.cvd",
        ]
        newest = 0
        for p in paths:
            if os.path.exists(p):
                mtime = os.path.getmtime(p)
                if mtime > newest:
                    newest = mtime
        if newest == 0:
            raise Exception("No se encontraron firmas")
        return (datetime.now() - datetime.fromtimestamp(newest)).days
