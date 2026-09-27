"""
core/sigma_engine.py
Cargador y evaluador de reglas Sigma (subset práctico).

Soporta construcciones usadas en producción:
  - Campos: CommandLine, Image, ParentImage, User, TargetFilename,
            DestinationIp, DestinationPort, EventType
  - Modificadores: contains, startswith, endswith, re, all
  - Condiciones: and, or, not, 1 of them, all of them
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("antivirus.sigma")


@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    description: str
    tags: list[str]
    detection: dict
    raw: dict

    def matches(self, event: dict) -> bool:
        return self._eval_condition(self.detection.get("condition", ""), event)

    def _eval_condition(self, condition: str, event: dict) -> bool:
        if not condition:
            return False

        if "of them" in condition:
            selections = [k for k in self.detection if k != "condition"]
            if condition.startswith("1 of"):
                return any(self._eval_selection(s, event) for s in selections)
            if condition.startswith("all of"):
                return all(self._eval_selection(s, event) for s in selections)

        expr = condition
        for sel in [k for k in self.detection if k != "condition"]:
            val = "True" if self._eval_selection(sel, event) else "False"
            expr = re.sub(rf"\b{re.escape(sel)}\b", val, expr)
        expr = expr.replace("and", " and ").replace("or", " or ").replace("not", " not ")
        try:
            return bool(eval(expr, {"__builtins__": {}}, {}))
        except Exception:
            return False

    def _eval_selection(self, name: str, event: dict) -> bool:
        sel = self.detection.get(name)
        if not isinstance(sel, dict):
            return False
        for field_expr, expected in sel.items():
            if not self._field_matches(field_expr, expected, event):
                return False
        return True

    def _field_matches(self, field_expr: str, expected: Any, event: dict) -> bool:
        parts = field_expr.split("|")
        field = parts[0]
        mods = parts[1:]
        value = event.get(field)

        if value is None:
            return False
        value = str(value)

        def _cmp(exp):
            exp = str(exp)
            if "contains" in mods:
                return exp.lower() in value.lower()
            if "startswith" in mods:
                return value.lower().startswith(exp.lower())
            if "endswith" in mods:
                return value.lower().endswith(exp.lower())
            if "re" in mods:
                try:
                    return bool(re.search(exp, value, re.IGNORECASE))
                except re.error:
                    return False
            return value.lower() == exp.lower()

        if isinstance(expected, list):
            if "all" in mods:
                return all(_cmp(e) for e in expected)
            return any(_cmp(e) for e in expected)
        return _cmp(expected)


class SigmaEngine:
    def __init__(self, rules_dir: str = "sigma_rules"):
        self.rules_dir = Path(rules_dir)
        self.rules: list[SigmaRule] = []
        self.load_rules()

    def load_rules(self):
        if not self.rules_dir.exists():
            logger.warning("Directorio de reglas Sigma no encontrado: %s", self.rules_dir)
            return
        count = 0
        for path in self.rules_dir.rglob("*.yml"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    docs = list(yaml.safe_load_all(f))
                for doc in docs:
                    if not doc or "detection" not in doc:
                        continue
                    rule = SigmaRule(
                        id=doc.get("id", path.stem),
                        title=doc.get("title", path.stem),
                        level=doc.get("level", "medium"),
                        description=doc.get("description", ""),
                        tags=doc.get("tags", []),
                        detection=doc["detection"],
                        raw=doc,
                    )
                    self.rules.append(rule)
                    count += 1
            except yaml.YAMLError as exc:
                logger.warning("YAML inválido en %s: %s", path, exc)
            except OSError as exc:
                logger.warning("No se pudo leer %s: %s", path, exc)
        logger.info("Cargadas %d reglas Sigma desde %s", count, self.rules_dir)

    def evaluate(self, event: dict) -> list[SigmaRule]:
        return [r for r in self.rules if r.matches(event)]
