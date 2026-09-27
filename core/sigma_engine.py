# core/sigma_engine.py
"""
Motor Sigma: parsea reglas YAML y las evalúa contra telemetría local.
"""
import os
import re
import fnmatch


class SigmaEngine:
    def __init__(self, config):
        self.config = config
        # Usar /tmp si no hay permisos en el path por defecto
        default_dir = config.get('sigma_rules_dir', '/opt/antivirus-pro/sigma_rules')
        self.rules_dir = self._safe_rules_dir(default_dir)
        self.rules = []
        self.rule_count = 0
        self._load_rules()

    def _safe_rules_dir(self, preferred):
        """Verifica permisos de escritura; si no, usa alternativa."""
        # Intento 1: directorio preferido
        try:
            os.makedirs(preferred, exist_ok=True)
            # Verificar escritura
            test_file = os.path.join(preferred, '.write_test')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            return preferred
        except (PermissionError, OSError):
            pass

        # Intento 2: directorio local del proyecto
        for candidate in ['./sigma_rules', './rules/sigma']:
            try:
                os.makedirs(candidate, exist_ok=True)
                test_file = os.path.join(candidate, '.write_test')
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
                return candidate
            except (PermissionError, OSError):
                continue

        # Fallback: /tmp
        tmp_dir = f'/tmp/sigma_rules_{os.getuid()}'
        os.makedirs(tmp_dir, exist_ok=True)
        return tmp_dir

    def _load_rules(self):
        """Carga todas las reglas Sigma YAML del directorio."""
        if not os.path.exists(self.rules_dir):
            return

        try:
            import yaml
        except ImportError:
            return

        for root, _, files in os.walk(self.rules_dir):
            for fname in files:
                if not fname.endswith(('.yml', '.yaml')):
                    continue
                path = os.path.join(root, fname)
                try:
                    with open(path, 'r') as f:
                        rule = yaml.safe_load(f)
                    if rule and isinstance(rule, dict) and 'detection' in rule:
                        rule['_path'] = path
                        self.rules.append(rule)
                except Exception:
                    pass

        self.rule_count = len(self.rules)

    def reload(self):
        """Recarga las reglas (útil tras descargar nuevas)."""
        self.rules = []
        self.rule_count = 0
        self._load_rules()
        return self.rule_count

    def match(self, event):
        """Evalúa un evento contra todas las reglas."""
        matches = []
        for rule in self.rules:
            try:
                if self._evaluate_rule(rule, event):
                    matches.append({
                        "engine": "sigma",
                        "threat": rule.get('title', 'Sigma rule'),
                        "severity": rule.get('level', 'medium'),
                        "confidence": 80,
                        "mitre": self._extract_mitre(rule),
                        "rule_id": rule.get('id', '')
                    })
            except Exception:
                pass
        return matches

    def _evaluate_rule(self, rule, event):
        detection = rule.get('detection', {})
        if not detection:
            return False

        condition = detection.get('condition', '')
        if not condition:
            return False

        selectors = {k: v for k, v in detection.items() if k != 'condition'}

        results = {}
        for name, selector in selectors.items():
            results[name] = self._evaluate_selector(selector, event)

        try:
            return self._eval_condition(condition, results)
        except Exception:
            return False

    def _evaluate_selector(self, selector, event):
        if isinstance(selector, list):
            return any(self._evaluate_selector(s, event) for s in selector)

        if isinstance(selector, dict):
            for field, value in selector.items():
                if not self._match_field(field, value, event):
                    return False
            return True

        return False

    def _match_field(self, field, value, event):
        field_lower = field.lower()
        event_value = None
        for k, v in event.items():
            if k.lower() == field_lower:
                event_value = v
                break

        if event_value is None:
            return False

        if isinstance(value, str):
            if value.startswith('*') and value.endswith('*'):
                return value.strip('*').lower() in str(event_value).lower()
            if value.startswith('*'):
                return str(event_value).lower().endswith(value[1:].lower())
            if value.endswith('*'):
                return str(event_value).lower().startswith(value[:-1].lower())
            return str(event_value).lower() == value.lower()

        if isinstance(value, list):
            return any(self._match_field(field, v, event) for v in value)

        return False

    def _eval_condition(self, condition, results):
        condition = condition.strip().lower()

        for name, val in results.items():
            condition = re.sub(rf'\b{re.escape(name)}\b', str(val), condition)

        condition = condition.replace(' and ', ' and ').replace(' or ', ' or ')

        if not re.match(r'^[\s\(\)TrueFalsendort]+$', condition):
            return False

        try:
            return bool(eval(condition))
        except Exception:
            return False

    def _extract_mitre(self, rule):
        tags = rule.get('tags', [])
        for tag in tags:
            if tag.startswith('attack.t'):
                return tag.replace('attack.', '').upper()
        return None
