"""
core/zero_day_engine.py
Motor de detección de día cero que orquesta:
  - Análisis estático (entropía, strings, IOCs)
  - Detección de anomalías ML (syscalls)
  - Generación automática de firmas YARA
  - Sandbox (opcional)

Proporciona una puntuación de riesgo unificada (0-1) basada en
múltiples capas de detección, reduciendo falsos positivos y
mejorando la detección de amenazas desconocidas.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .static_analyzer import StaticAnalyzer, StaticAnalysisResult
from .ml_detector import SyscallAnomalyDetector, AnomalyResult
from .yara_generator import YaraRuleGenerator, GeneratedRule
from .sandbox import Sandbox, SandboxResult

logger = logging.getLogger("antivirus.zero_day")


@dataclass
class ZeroDayVerdict:
    filepath: str
    risk_score: float
    is_malicious: bool
    reasons: list[str] = field(default_factory=list)
    static_result: StaticAnalysisResult | None = None
    anomaly_result: AnomalyResult | None = None
    sandbox_result: SandboxResult | None = None
    generated_rule: GeneratedRule | None = None


class ZeroDayEngine:
    """
    Motor de detección de día cero con múltiples capas.
    """

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self.static = StaticAnalyzer()
        self.ml = SyscallAnomalyDetector()
        # YaraRuleGenerator con ruta configurable. Por defecto intenta
        # escribir en /var/lib/antivirus-linux-dragon/yara_rules_generated
        # para evitar problemas de permisos en producción.
        yara_gen_dir = self.config.get(
            "yara_generated_dir",
            "/var/lib/antivirus-linux-dragon/yara_rules_generated",
        )
        try:
            self.yara_gen = YaraRuleGenerator(yara_gen_dir)
        except (PermissionError, OSError) as exc:
            logger.warning(
                "No se pudo usar %s para reglas YARA (%s). Usando fallback.",
                yara_gen_dir, exc,
            )
            self.yara_gen = YaraRuleGenerator()
        self.sandbox = Sandbox(enabled=self.config.get("sandbox_enabled", True))
        self.risk_threshold = self.config.get("risk_threshold", 0.6)

        # Intentar cargar modelo ML pre-entrenado
        if not self.ml.load():
            logger.info("No hay modelo ML pre-entrenado. Entrena con: "
                       "zero_day_engine.train_ml(benign_sequences)")

    def train_ml(self, benign_sequences: list[list[str]]) -> None:
        """Entrena el detector ML con secuencias benignas."""
        self.ml.train(benign_sequences)
        self.ml.save()

    def evaluate(self, filepath: str, syscall_sequence: list[str] | None = None) -> ZeroDayVerdict:
        """
        Evalúa un archivo con todas las capas disponibles.

        :param filepath: Archivo a evaluar.
        :param syscall_sequence: Secuencia de syscalls capturada (si aplica).
        """
        reasons = []
        layer_scores: list[float] = []  # score de cada capa, 0-1

        # 1. Análisis estático
        static_result = None
        try:
            static_result = self.static.analyze(filepath)
            layer_scores.append(static_result.score)
            if static_result.is_packed:
                reasons.append(f"Empaquetado (entropía {static_result.global_entropy:.2f})")
            if static_result.suspicious_strings:
                reasons.append(
                    f"Strings sospechosos: {', '.join(static_result.suspicious_strings[:3])}"
                )
            if static_result.embedded_iocs.get("urls"):
                reasons.append(
                    f"{len(static_result.embedded_iocs['urls'])} URLs embebidas"
                )
        except Exception as exc:
            logger.warning("Error en análisis estático de %s: %s", filepath, exc)

        # 2. Detección de anomalías ML (si hay secuencia)
        anomaly_result = None
        if syscall_sequence and self.ml.is_trained:
            anomaly_result = self.ml.score(syscall_sequence)
            if anomaly_result.is_anomalous:
                # Un score ML de 0.7 cuenta como 0.7
                ml_score = max(
                    anomaly_result.path_score_a,
                    anomaly_result.path_score_b,
                    anomaly_result.path_score_c,
                )
                layer_scores.append(ml_score)
                reasons.append(anomaly_result.reason)

        # 3. Sandbox (opcional, costoso)
        sandbox_result = None
        if self.config.get("sandbox_enabled", False) and self.sandbox.enabled:
            sandbox_result = self.sandbox.detonate(filepath)
            if sandbox_result.executed:
                if sandbox_result.network_attempts:
                    layer_scores.append(0.7)
                    reasons.append(
                        f"Intentos de red en sandbox: {len(sandbox_result.network_attempts)}"
                    )

        # 4. Fusión de capas: máximo de los scores individuales.
        #    Cualquier capa que dispare anomalía fuerte marca el archivo.
        #    Esto refleja que la detección es un OR lógico, no una AND.
        risk = max(layer_scores) if layer_scores else 0.0
        is_malicious = risk >= self.risk_threshold

        # 5. Generar regla YARA si se considera malicioso
        generated_rule = None
        if is_malicious:
            try:
                generated_rule = self.yara_gen.generate_from_file(filepath)
                if generated_rule:
                    reasons.append(f"Regla YARA generada: {generated_rule.name}")
            except Exception as exc:
                logger.warning("Error generando regla YARA: %s", exc)

        return ZeroDayVerdict(
            filepath=filepath,
            risk_score=risk,
            is_malicious=is_malicious,
            reasons=reasons,
            static_result=static_result,
            anomaly_result=anomaly_result,
            sandbox_result=sandbox_result,
            generated_rule=generated_rule,
        )
