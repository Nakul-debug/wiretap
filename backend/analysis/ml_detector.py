"""ML-based anomaly detection for network packet streams.

This module provides an unsupervised anomaly detector built on
scikit-learn's Isolation Forest. It extracts numeric features from
each :class:`SourceProfile` and flags sources whose behaviour deviates
significantly from the learned baseline.

Because wiretap is educational and typically has no labelled training
data, the detector is *unsupervised*: it learns what "normal" looks
like from the observed traffic itself and marks outliers as potential
threats.

Usage::

    from wiretap.analysis import MLAnomalyDetector, ThreatAlert

    detector = MLAnomalyDetector(contamination=0.05)

    def on_alert(alert: ThreatAlert):
        print(f"ML anomaly: {alert.source_ip} ({alert.threat_type})")

    detector = MLAnomalyDetector(alert_callback=on_alert)
    detector.analyse(packet)   # call for every captured packet
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, List, Optional, Sequence, Set

from backend.models.packet import Packet
from backend.models.threat_alert import ThreatAlert
from backend.analysis.threat_detector import SourceProfile

logger = logging.getLogger(__name__)

# Optional scikit-learn import. The detector degrades gracefully if
# scikit-learn is not installed.
try:  # pragma: no cover - environment dependent
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    _SKLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover - environment dependent
    IsolationForest = None  # type: ignore[assignment]
    StandardScaler = None  # type: ignore[assignment]
    _SKLEARN_AVAILABLE = False


# Feature names in the fixed order used by the model.
FEATURE_NAMES: List[str] = [
    "packet_rate",            # packets per second (recent window)
    "byte_rate",              # bytes per second (recent window)
    "unique_port_count",      # distinct destination ports
    "unique_ip_count",        # distinct destination IPs
    "syn_ratio",              # SYN packets / total packets
    "avg_packet_size",        # mean recent packet size
    "size_std",               # std dev of recent packet sizes
    "duration",               # seconds since first seen
    "interval_cv",            # coefficient of variation of inter-arrival times
]


@dataclass
class MLAnomalyResult:
    """Result of a single ML anomaly evaluation."""

    source_ip: str
    is_anomaly: bool
    anomaly_score: float   # Isolation Forest score (lower = more anomalous)
    confidence: float      # 0.0 to 1.0, derived from the score
    features: Dict[str, float]
    trained: bool          # whether the model had been trained at evaluation time


class MLAnomalyDetector:
    """Unsupervised ML anomaly detector using Isolation Forest.

    Parameters
    ----------
    alert_callback:
        Optional callback invoked whenever an anomaly is detected.
    contamination:
        Expected proportion of anomalies in the data (passed to
        ``IsolationForest``). Lower = fewer false positives.
    retrain_interval:
        Seconds between model retraining cycles.
    min_samples:
        Minimum number of feature vectors required before training.
    window_seconds:
        Recent window (seconds) used for rate/size features.
    anomaly_threshold:
        Decision-function threshold below which a sample is flagged.
        If None, the model's internal ``contamination``-based threshold
        is used.
    """

    def __init__(
        self,
        alert_callback: Optional[Callable[[ThreatAlert], None]] = None,
        contamination: float = 0.05,
        retrain_interval: float = 60.0,
        min_samples: int = 50,
        window_seconds: float = 60.0,
        anomaly_threshold: Optional[float] = None,
    ) -> None:
        self.alert_callback = alert_callback
        self.contamination = contamination
        self.retrain_interval = retrain_interval
        self.min_samples = min_samples
        self.window_seconds = window_seconds
        self.anomaly_threshold = anomaly_threshold

        if not _SKLEARN_AVAILABLE:
            logger.warning(
                "scikit-learn is not installed; MLAnomalyDetector will not "
                "detect anomalies. Install it with: pip install scikit-learn"
            )

        self._model: Optional[IsolationForest] = None
        self._scaler: Optional[StandardScaler] = None
        self._feature_history: Deque[List[float]] = deque(maxlen=5000)
        self._source_features: Dict[str, List[float]] = {}
        self._aggregates: Dict[str, _RunningAggregate] = {}
        self._alerted_sources: Set[str] = set()
        self._lock = threading.Lock()
        self._last_retrain: float = 0.0
        self._trained = False
        self._alerts: List[ThreatAlert] = []

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    @property
    def is_available(self) -> bool:
        """Return True if scikit-learn is installed and the detector works."""
        return _SKLEARN_AVAILABLE

    @property
    def is_trained(self) -> bool:
        return self._trained

    def analyse(self, packet: Packet) -> Optional[ThreatAlert]:
        """Process one packet and return an alert if it looks anomalous.

        Returns ``None`` if scikit-learn is unavailable, the model is not
        yet trained, or the packet is not anomalous.
        """
        if not _SKLEARN_AVAILABLE:
            return None

        src_ip = self._extract_source_ip(packet)
        if not src_ip:
            return None

        # One alert per source IP — skip if already alerted
        with self._lock:
            if src_ip in self._alerted_sources:
                return None

        features = self._extract_features(packet)
        if features is None:
            return None

        feature_vector = [features[name] for name in FEATURE_NAMES]

        with self._lock:
            self._source_features[src_ip] = feature_vector
            self._feature_history.append(feature_vector)

            # Retrain periodically when we have enough samples.
            now = time.time()
            if (
                not self._trained
                or now - self._last_retrain > self.retrain_interval
            ) and len(self._feature_history) >= self.min_samples:
                self._train()
                self._last_retrain = now

            if not self._trained:
                return None

            # Score the current source's feature vector.
            anomaly_score, is_anomaly = self._score(feature_vector)

        if is_anomaly:
            confidence = self._score_to_confidence(anomaly_score)
            alert = ThreatAlert(
                source_ip=src_ip,
                threat_type="ml_anomaly",
                severity=self._severity_from_confidence(confidence),
                confidence=confidence,
                description=(
                    "ML anomaly detection flagged unusual traffic behaviour "
                    f"from {src_ip} (Isolation Forest score {anomaly_score:.3f})."
                ),
                evidence={
                    "anomaly_score": anomaly_score,
                    "features": features,
                    "contamination": self.contamination,
                },
                is_malicious=True,
            )
            self._alerts.append(alert)
            self._alerted_sources.add(src_ip)
            if self.alert_callback:
                try:
                    self.alert_callback(alert)
                except Exception as exc:  # pragma: no cover - callback safety
                    logger.error("ML alert callback raised: %s", exc)
            return alert
        return None

    def analyse_batch(self, packets: Sequence[Packet]) -> List[ThreatAlert]:
        """Process multiple packets, returning all alerts raised."""
        alerts: List[ThreatAlert] = []
        for pkt in packets:
            alert = self.analyse(pkt)
            if alert:
                alerts.append(alert)
        return alerts

    def get_alerts(self) -> List[ThreatAlert]:
        with self._lock:
            return list(self._alerts)

    def reset(self) -> None:
        with self._lock:
            self._feature_history.clear()
            self._source_features.clear()
            self._model = None
            self._scaler = None
            self._trained = False
            self._alerts.clear()
            self._last_retrain = 0.0

    # ------------------------------------------------------------------ #
    # Internal: feature extraction
    # ------------------------------------------------------------------ #
    def _extract_source_ip(self, packet: Packet) -> Optional[str]:
        ip = packet.get_layer("IPv4") or packet.get_layer("IPv6")
        if not ip:
            return None
        src = ip.get_field("src_addr") or ip.get_field("source")
        return str(src) if src else None

    def _extract_features(self, packet: Packet) -> Optional[Dict[str, float]]:
        """Build a feature dictionary for the packet's source.

        Uses the live :class:`SourceProfile`-like aggregation stored in
        ``_source_features`` plus the current packet. We keep running
        aggregates in memory keyed by source IP.
        """
        src_ip = self._extract_source_ip(packet)
        if not src_ip:
            return None

        timestamp = packet.timestamp
        pkt_len = len(packet.raw_bytes) if packet.raw_bytes else 0

        # Retrieve or initialise the running aggregate for this source.
        agg = self._aggregates.get(src_ip)
        if agg is None:
            agg = _RunningAggregate()
            self._aggregates[src_ip] = agg

        agg.update(pkt_len, timestamp)

        # Inter-arrival coefficient of variation.
        intervals = agg.intervals
        if len(intervals) >= 2:
            mean_iv = sum(intervals) / len(intervals)
            var = sum((i - mean_iv) ** 2 for i in intervals) / len(intervals)
            std = var ** 0.5
            interval_cv = std / mean_iv if mean_iv > 0 else 0.0
        else:
            interval_cv = 0.0

        window = self.window_seconds
        now = timestamp
        cutoff = now - window
        recent_packets = [t for t in agg.timestamps if t >= cutoff]
        pps = len(recent_packets) / max(window, 1e-6)

        recent_bytes = [
            agg.byte_samples[i]
            for i, t in enumerate(agg.timestamps)
            if t >= cutoff
        ]
        bps = sum(recent_bytes) / max(window, 1e-6)

        syn_ratio = agg.syn_count / max(agg.packet_count, 1)
        avg_size = agg.size_sum / max(agg.packet_count, 1)
        size_std = agg.size_std()

        features = {
            "packet_rate": pps,
            "byte_rate": bps,
            "unique_port_count": float(len(agg.destination_ports)),
            "unique_ip_count": float(len(agg.destination_ips)),
            "syn_ratio": syn_ratio,
            "avg_packet_size": avg_size,
            "size_std": size_std,
            "duration": max(now - agg.first_seen, 1e-6),
            "interval_cv": interval_cv,
        }
        return features

    # ------------------------------------------------------------------ #
    # Internal: model training / scoring
    # ------------------------------------------------------------------ #
    def _train(self) -> None:
        if len(self._feature_history) < self.min_samples:
            return

        X = [list(v) for v in self._feature_history]
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        self._model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
            max_samples="auto",
            n_jobs=-1,
        )
        self._model.fit(X_scaled)
        self._trained = True
        logger.info(
            "ML anomaly model trained on %d samples (contamination=%.2f)",
            len(X),
            self.contamination,
        )

    def _score(self, feature_vector: Sequence[float]) -> tuple[float, bool]:
        """Return (anomaly_score, is_anomaly) for a single feature vector."""
        assert self._model is not None and self._scaler is not None
        X_scaled = self._scaler.transform([list(feature_vector)])
        score = float(self._model.decision_function(X_scaled)[0])
        threshold = self.anomaly_threshold
        if threshold is None:
            # IsolationForest.predict returns -1 for anomalies, 1 otherwise.
            pred = int(self._model.predict(X_scaled)[0])
            is_anomaly = pred == -1
        else:
            is_anomaly = score < threshold
        return score, is_anomaly

    @staticmethod
    def _score_to_confidence(score: float) -> float:
        """Map an Isolation Forest decision score to a 0–1 confidence."""
        # Isolation Forest scores are typically in [-1, 0.5]; lower = more anomalous.
        # Use a simple sigmoid-like mapping centred around -0.1.
        import math

        confidence = 1.0 / (1.0 + math.exp(5.0 * (score + 0.1)))
        return max(0.0, min(1.0, confidence))

    @staticmethod
    def _severity_from_confidence(confidence: float) -> str:
        if confidence >= 0.8:
            return "high"
        if confidence >= 0.6:
            return "medium"
        return "low"


# --------------------------------------------------------------------------- #
# Helper: running aggregate per source (used for feature extraction)
# --------------------------------------------------------------------------- #
@dataclass
class _RunningAggregate:
    """Running per-source statistics used to build feature vectors."""

    packet_count: int = 0
    byte_count: int = 0
    size_sum: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    syn_count: int = 0
    destination_ports: set = field(default_factory=set)
    destination_ips: set = field(default_factory=set)

    # Rolling windows
    timestamps: deque = field(default_factory=lambda: deque(maxlen=2000))
    byte_samples: deque = field(default_factory=lambda: deque(maxlen=2000))
    intervals: deque = field(default_factory=lambda: deque(maxlen=2000))

    def update(self, packet_length: int, timestamp: float) -> None:
        self.packet_count += 1
        self.byte_count += packet_length
        self.size_sum += packet_length
        self.last_seen = timestamp

        if self.timestamps:
            self.intervals.append(timestamp - self.timestamps[-1])
        self.timestamps.append(timestamp)
        self.byte_samples.append(packet_length)

    def size_std(self) -> float:
        if len(self.byte_samples) < 2:
            return 0.0
        values = list(self.byte_samples)
        mean = sum(values) / len(values)
        var = sum((v - mean) ** 2 for v in values) / len(values)
        return var ** 0.5
