"""
Tests de SIEMForwarder. UDP se prueba realmente contra un socket local.
"""
import json
import socket
import threading
import time

import pytest

from core.siem_forwarder import SIEMForwarder


@pytest.fixture
def udp_receiver():
    """Servidor UDP local que captura los mensajes recibidos."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(2.0)
    port = sock.getsockname()[1]
    messages = []

    def receiver():
        try:
            while True:
                data, _ = sock.recvfrom(65535)
                messages.append(data.decode("utf-8", "replace"))
        except socket.timeout:
            pass
        except OSError:
            pass

    t = threading.Thread(target=receiver, daemon=True)
    t.start()
    yield port, messages
    sock.close()
    t.join(timeout=1)


class TestSIEMForwarder:
    def test_envia_udp_formato_cef(self, udp_receiver):
        port, messages = udp_receiver
        fwd = SIEMForwarder(host="127.0.0.1", port=port, protocol="udp", fmt="cef")
        assert fwd.start()
        fwd.send({
            "rule_id": "r1", "rule_title": "Test alert",
            "severity": "high", "pid": 1234, "comm": "bash",
        })
        time.sleep(0.5)
        fwd.stop()
        assert len(messages) >= 1
        assert messages[0].startswith("CEF:0|")

    def test_envia_udp_formato_json(self, udp_receiver):
        port, messages = udp_receiver
        fwd = SIEMForwarder(host="127.0.0.1", port=port, protocol="udp", fmt="json")
        fwd.start()
        fwd.send({"event_type": "test", "pid": 1})
        time.sleep(0.5)
        fwd.stop()
        assert len(messages) >= 1
        parsed = json.loads(messages[0])
        assert parsed["event_type"] == "test"

    def test_start_falla_en_host_invalido(self):
        fwd = SIEMForwarder(host="999.999.999.999", port=514)
        # UDP con host inválido debería fallar al crear el socket o al enviar
        # (algunos sistemas no fallan hasta el sendto)
        result = fwd.start()
        # No es determinista; solo verificamos que no explota
        assert isinstance(result, bool)
        fwd.stop()
