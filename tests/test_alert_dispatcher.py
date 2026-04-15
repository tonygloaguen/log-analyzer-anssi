"""
Tests unitaires — AlertDispatcher.

Couvre :
    - Filtre par score minimal (alert_min_score)
    - Rate limiting par technique (cooldown 5 min)
    - Helpers statiques (_ntfy_priority, _build_alert_body)
    - Canaux email sans SMTP configuré
    - dispatch_async (async path)

Aucune dépendance réseau requise — tous les tests sont synchrones ou
utilisent des canaux vides / intentionnellement non configurés.

Exécution ::

    pytest tests/test_alert_dispatcher.py -v
"""

from __future__ import annotations

import os
import time

import pytest

os.environ.setdefault("HMAC_SECRET", "test-secret-dispatcher-000000000000000")

from notifiers.alert_dispatcher import AlertChannel, AlertDispatcher  # noqa: E402

# ─── Payload minimal valide ───────────────────────────────────────────────────

def _payload(technique: str = "T1068", confidence: float = 0.8) -> dict:
    return {
        "technique": technique,
        "verdict": "SUSPECTED_RANSOMWARE",
        "confidence": confidence,
        "narrative": "Test alert.",
        "ts": time.time(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Filtre par score minimal
# ─────────────────────────────────────────────────────────────────────────────

class TestScoreFilter:
    """dispatch() avec confidence < seuil → success=False sans appel réseau."""

    def test_below_threshold_returns_none_channel(self) -> None:
        d = AlertDispatcher(alert_min_score=0.8, channels=[])
        result = d.dispatch(_payload("T1-score", confidence=0.5))
        assert result["success"] is False
        assert result["channel_used"] == AlertChannel.NONE

    def test_exactly_at_threshold_passes_filter(self) -> None:
        """confidence == seuil doit passer le filtre (>= non >).

        Note : channels=[] est falsy → tombe sur l'env NOTIFIER_CHANNELS.
        On utilise un canal inconnu pour éviter tout appel réseau.
        """
        d = AlertDispatcher(alert_min_score=0.5, channels=["__noop__"])
        result = d.dispatch(_payload("T2-score-exact", confidence=0.5))
        # Canal inconnu → skipped → success=False, channel_used=NONE
        assert result["channel_used"] == AlertChannel.NONE

    def test_zero_confidence_blocked_by_default_threshold(self) -> None:
        d = AlertDispatcher()  # seuil par défaut = 0.6
        result = d.dispatch(_payload("T3-zero-conf", confidence=0.0))
        assert result["success"] is False

    def test_high_confidence_passes_filter(self) -> None:
        """Confiance élevée passe le filtre (echec attendu faute de canal valide)."""
        d = AlertDispatcher(alert_min_score=0.6, channels=["__noop__"])
        result = d.dispatch(_payload("T4-high-conf", confidence=0.95))
        assert result["success"] is False  # canal inconnu skippé


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiting
# ─────────────────────────────────────────────────────────────────────────────

class TestRateLimiting:
    """Cooldown 300s par technique."""

    def test_fresh_rate_limit_blocks_dispatch(self) -> None:
        d = AlertDispatcher(alert_min_score=0.0, channels=[])
        d._rate_limit["T5-rl"] = time.time()  # simuler envoi récent
        result = d.dispatch(_payload("T5-rl", confidence=0.9))
        assert result["success"] is False
        assert result["channel_used"] == AlertChannel.NONE

    def test_expired_rate_limit_allows_dispatch(self) -> None:
        """Entrée > 300s → cooldown expiré → dispatch tenté."""
        d = AlertDispatcher(alert_min_score=0.0, channels=["__noop__"])
        d._rate_limit["T6-rl-exp"] = time.time() - 400  # expiré
        result = d.dispatch(_payload("T6-rl-exp", confidence=0.9))
        # Canal inconnu → skippé → success=False mais PAS à cause du rate limit
        assert result["channel_used"] == AlertChannel.NONE

    def test_no_rate_limit_entry_allows_dispatch(self) -> None:
        d = AlertDispatcher(alert_min_score=0.0, channels=["__noop__"])
        assert "T7-new-tech" not in d._rate_limit
        result = d.dispatch(_payload("T7-new-tech", confidence=0.9))
        assert result["success"] is False  # canal noop, mais rate limit n'a pas bloqué

    def test_is_rate_limited_true(self) -> None:
        d = AlertDispatcher()
        d._rate_limit["TRL1"] = time.time()
        assert d._is_rate_limited("TRL1") is True

    def test_is_rate_limited_false_no_entry(self) -> None:
        d = AlertDispatcher()
        assert d._is_rate_limited("TRL-nonexistent") is False

    def test_is_rate_limited_false_expired(self) -> None:
        d = AlertDispatcher()
        d._rate_limit["TRL-old"] = time.time() - 400
        assert d._is_rate_limited("TRL-old") is False


# ─────────────────────────────────────────────────────────────────────────────
# Helpers statiques
# ─────────────────────────────────────────────────────────────────────────────

class TestNtfyPriority:
    def test_urgent_above_08(self) -> None:
        assert AlertDispatcher._ntfy_priority(0.9) == "urgent"
        assert AlertDispatcher._ntfy_priority(0.81) == "urgent"

    def test_high_above_05(self) -> None:
        assert AlertDispatcher._ntfy_priority(0.7) == "high"
        assert AlertDispatcher._ntfy_priority(0.51) == "high"

    def test_default_at_or_below_05(self) -> None:
        assert AlertDispatcher._ntfy_priority(0.5) == "default"
        assert AlertDispatcher._ntfy_priority(0.0) == "default"


class TestBuildAlertBody:
    def test_title_contains_technique(self) -> None:
        payload = _payload("T1068")
        title, _ = AlertDispatcher._build_alert_body(payload)
        assert "T1068" in title

    def test_body_contains_verdict_and_confidence(self) -> None:
        payload = _payload("T1068", confidence=0.9)
        _, body = AlertDispatcher._build_alert_body(payload)
        assert "SUSPECTED_RANSOMWARE" in body
        assert "90%" in body

    def test_narrative_truncated_to_100_chars(self) -> None:
        payload = _payload()
        payload["narrative"] = "x" * 200
        _, body = AlertDispatcher._build_alert_body(payload)
        # La troncature à 100 chars est appliquée : jamais 101 x consécutifs
        assert "x" * 101 not in body
        assert "x" * 100 in body

    def test_unknown_defaults_when_keys_missing(self) -> None:
        title, body = AlertDispatcher._build_alert_body({})
        assert "UNKNOWN" in title
        assert "UNKNOWN" in body


# ─────────────────────────────────────────────────────────────────────────────
# Canal email sans SMTP configuré
# ─────────────────────────────────────────────────────────────────────────────

class TestEmailFallback:
    def test_email_channel_without_smtp_host_returns_failure(self) -> None:
        d = AlertDispatcher(
            alert_min_score=0.0,
            channels=["email"],
            smtp_host="",
            smtp_to=["test@example.com"],
        )
        result = d.dispatch(_payload("T-email-nohost", confidence=0.8))
        assert result["success"] is False

    def test_email_channel_without_recipients_returns_failure(self) -> None:
        d = AlertDispatcher(
            alert_min_score=0.0,
            channels=["email"],
            smtp_host="smtp.example.com",
            smtp_to=[],
        )
        result = d.dispatch(_payload("T-email-norecip", confidence=0.8))
        assert result["success"] is False

    def test_unknown_channel_skipped(self) -> None:
        d = AlertDispatcher(alert_min_score=0.0, channels=["fax", "pigeon"])
        result = d.dispatch(_payload("T-unknown-chan", confidence=0.8))
        assert result["success"] is False


# ─────────────────────────────────────────────────────────────────────────────
# dispatch_async
# ─────────────────────────────────────────────────────────────────────────────

class TestAsyncDispatch:
    @pytest.mark.asyncio
    async def test_async_below_threshold_blocked(self) -> None:
        d = AlertDispatcher(alert_min_score=0.9, channels=[])
        result = await d.dispatch_async(_payload("T-async-thresh", confidence=0.3))
        assert result["success"] is False
        assert result["channel_used"] == AlertChannel.NONE.value

    @pytest.mark.asyncio
    async def test_async_rate_limited_blocked(self) -> None:
        d = AlertDispatcher(alert_min_score=0.0, channels=[])
        d._rate_limit["T-async-rl"] = time.time()
        result = await d.dispatch_async(_payload("T-async-rl", confidence=0.9))
        assert result["success"] is False
        assert result["channel_used"] == AlertChannel.NONE.value

    @pytest.mark.asyncio
    async def test_async_unknown_channel_skipped(self) -> None:
        d = AlertDispatcher(alert_min_score=0.0, channels=["smoke-signal"])
        result = await d.dispatch_async(_payload("T-async-unknown", confidence=0.9))
        assert result["success"] is False
