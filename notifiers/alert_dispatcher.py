"""
Dispatcher d'alertes — ntfy (canal principal) + email SMTP (fallback).

Channels configurables via NOTIFIER_CHANNELS (ordre = priorité).
Rate limiting en mémoire : 1 alerte par technique par 5 minutes.

Variables d'environnement :
    NOTIFIER_CHANNELS  Canaux ordonnés (défaut : ``ntfy,email``).
    NTFY_URL           URL base ntfy (défaut : ``http://localhost:8080``).
    NTFY_TOPIC         Topic ntfy (défaut : ``log-analyzer-alerts``).
    NTFY_TOKEN         Token d'authentification ntfy (optionnel).
    SMTP_HOST          Serveur SMTP.
    SMTP_PORT          Port SMTP (défaut : 587).
    SMTP_USER          Identifiant SMTP.
    SMTP_PASS          Mot de passe SMTP.
    SMTP_FROM          Adresse expéditeur.
    ALERT_EMAIL_TO     Adresse(s) destinataire(s), séparées par virgule.
    SMTP_USE_TLS       Activer STARTTLS (défaut : ``true``).
    ALERT_MIN_SCORE    Score minimal pour déclencher une alerte (défaut : 0.6).

Conformité ANSSI :
    - Aucune donnée de log brute dans les notifications (résumé uniquement).
    - STARTTLS obligatoire sur SMTP.
"""

from __future__ import annotations

import asyncio
import logging
import os
import smtplib
import time
from dataclasses import dataclass
from email.message import EmailMessage
from enum import Enum
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_RATE_LIMIT_SECONDS = 300  # 5 minutes par technique
_NTFY_TITLE_MAX = 250
_NTFY_BODY_MAX = 4096


class AlertChannel(str, Enum):
    """Canal de notification effectivement utilisé."""

    NTFY = "ntfy"
    EMAIL = "email"
    NONE = "none"


@dataclass
class AlertResult:
    """Résultat d'une tentative d'envoi d'alerte.

    Attributes:
        channel: Canal effectivement utilisé.
        success: ``True`` si l'alerte a bien été envoyée.
        message_id: Identifiant de message retourné par le canal.
        error: Message d'erreur en cas d'échec.
    """

    channel: AlertChannel
    success: bool
    message_id: str = ""
    error: str = ""


class AlertDispatcher:
    """Dispatcher d'alertes multi-canal avec rate limiting en mémoire.

    L'ordre des canaux dans ``NOTIFIER_CHANNELS`` détermine la priorité.
    Le fallback s'active si le canal principal échoue.

    Args:
        ntfy_url: URL base ntfy.
        ntfy_topic: Topic ntfy.
        ntfy_token: Token d'authentification ntfy (None = accès public).
        smtp_host: Hôte SMTP.
        smtp_port: Port SMTP (587 pour STARTTLS).
        smtp_user: Identifiant SMTP.
        smtp_password: Mot de passe SMTP.
        smtp_from: Adresse expéditeur.
        smtp_to: Liste des destinataires.
        smtp_use_tls: Activer STARTTLS (fortement recommandé).
        alert_min_score: Score minimal pour déclencher une alerte.
        channels: Ordre des canaux (remplace NOTIFIER_CHANNELS).
    """

    def __init__(
        self,
        ntfy_url: str | None = None,
        ntfy_topic: str | None = None,
        ntfy_token: str | None = None,
        smtp_host: str | None = None,
        smtp_port: int | None = None,
        smtp_user: str | None = None,
        smtp_password: str | None = None,
        smtp_from: str | None = None,
        smtp_to: list[str] | None = None,
        smtp_use_tls: bool | None = None,
        alert_min_score: float | None = None,
        channels: list[str] | None = None,
    ) -> None:
        # Channels configurables (env en fallback)
        env_channels = os.environ.get("NOTIFIER_CHANNELS", "ntfy,email")
        self._channels: list[str] = channels or [c.strip() for c in env_channels.split(",") if c.strip()]

        # ntfy
        self._ntfy_url = ntfy_url or os.environ.get("NTFY_URL", "http://localhost:8080")
        self._ntfy_topic = ntfy_topic or os.environ.get("NTFY_TOPIC", "log-analyzer-alerts")
        self._ntfy_token = ntfy_token or os.environ.get("NTFY_TOKEN") or None

        # SMTP
        self._smtp_host = smtp_host or os.environ.get("SMTP_HOST", "")
        self._smtp_port = smtp_port if smtp_port is not None else int(os.environ.get("SMTP_PORT", "587"))
        self._smtp_user = smtp_user or os.environ.get("SMTP_USER", "")
        self._smtp_password = smtp_password or os.environ.get("SMTP_PASS", "")
        self._smtp_from = smtp_from or os.environ.get("SMTP_FROM", "")
        smtp_to_env = os.environ.get("ALERT_EMAIL_TO", "")
        self._smtp_to: list[str] = smtp_to or [r.strip() for r in smtp_to_env.split(",") if r.strip()]
        self._smtp_use_tls = smtp_use_tls if smtp_use_tls is not None else (
            os.environ.get("SMTP_USE_TLS", "true").lower() != "false"
        )

        # Seuil minimal
        self._alert_min_score = alert_min_score if alert_min_score is not None else float(
            os.environ.get("ALERT_MIN_SCORE", "0.6")
        )

        # Rate limiting : {technique: last_sent_ts}
        self._rate_limit: dict[str, float] = {}

    # ─── API publique ─────────────────────────────────────────────────────────

    def dispatch(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Envoie une alerte via les canaux configurés (synchrone, thread-safe).

        Respecte le rate limiting par technique (1 alerte / 5 min).
        Essaie les canaux dans l'ordre configuré jusqu'au premier succès.

        Args:
            payload: Dict produit par le nœud ``ransomware_behavior_analyst``
                     Clés attendues : ``verdict``, ``confidence``, ``technique``,
                     ``narrative``, ``ts``.

        Returns:
            Dict ``{"channel_used": str, "success": bool, "ts": float}``.
        """
        confidence: float = float(payload.get("confidence", 0.0))
        technique: str = str(payload.get("technique", "UNKNOWN"))

        # Filtre par score minimal
        if confidence < self._alert_min_score:
            logger.debug(
                "[AlertDispatcher] Alerte ignorée (confidence=%.2f < seuil=%.2f)",
                confidence, self._alert_min_score,
            )
            return {"channel_used": AlertChannel.NONE, "success": False, "ts": time.time()}

        # Rate limiting par technique
        if self._is_rate_limited(technique):
            logger.info(
                "[AlertDispatcher] Rate-limited : technique=%s (cooldown %ds)",
                technique, _RATE_LIMIT_SECONDS,
            )
            return {"channel_used": AlertChannel.NONE, "success": False, "ts": time.time()}

        title, body = self._build_alert_body(payload)
        priority = self._ntfy_priority(confidence)

        result: AlertResult = AlertResult(channel=AlertChannel.NONE, success=False)

        for channel in self._channels:
            ch = channel.lower()
            if ch == "ntfy":
                result = asyncio.get_event_loop().run_until_complete(
                    self._send_ntfy(title, body, priority)
                ) if not asyncio.get_event_loop().is_running() else self._send_ntfy_sync(title, body, priority)
            elif ch == "email":
                result = self._send_email_sync(title, body)
            else:
                logger.warning("[AlertDispatcher] Canal inconnu ignoré : %s", channel)
                continue

            if result.success:
                self._rate_limit[technique] = time.time()
                logger.info(
                    "[AlertDispatcher] Alerte envoyée via %s (technique=%s, confidence=%.2f)",
                    result.channel, technique, confidence,
                )
                break
            else:
                logger.warning(
                    "[AlertDispatcher] Canal %s échoué (%s) — essai suivant",
                    ch, result.error,
                )

        return {
            "channel_used": result.channel.value if result.channel else AlertChannel.NONE.value,
            "success": result.success,
            "ts": time.time(),
        }

    async def dispatch_async(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Version asynchrone de :meth:`dispatch`.

        Args:
            payload: Dict d'alerte (même format que :meth:`dispatch`).

        Returns:
            Dict ``{"channel_used": str, "success": bool, "ts": float}``.
        """
        confidence: float = float(payload.get("confidence", 0.0))
        technique: str = str(payload.get("technique", "UNKNOWN"))

        if confidence < self._alert_min_score:
            return {"channel_used": AlertChannel.NONE.value, "success": False, "ts": time.time()}

        if self._is_rate_limited(technique):
            return {"channel_used": AlertChannel.NONE.value, "success": False, "ts": time.time()}

        title, body = self._build_alert_body(payload)
        priority = self._ntfy_priority(confidence)
        result: AlertResult = AlertResult(channel=AlertChannel.NONE, success=False)

        for channel in self._channels:
            ch = channel.lower()
            if ch == "ntfy":
                result = await self._send_ntfy(title, body, priority)
            elif ch == "email":
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, self._send_email_sync, title, body)
            else:
                continue

            if result.success:
                self._rate_limit[technique] = time.time()
                break

        return {
            "channel_used": result.channel.value,
            "success": result.success,
            "ts": time.time(),
        }

    # ─── ntfy ────────────────────────────────────────────────────────────────

    async def _send_ntfy(self, title: str, body: str, priority: str) -> AlertResult:
        """Envoie une notification push via ntfy (async httpx).

        Args:
            title: Titre de la notification (max 250 caractères).
            body: Corps (résumé de l'incident, sans données brutes).
            priority: Priorité ntfy (``default``, ``high``, ``urgent``).

        Returns:
            :class:`AlertResult`.
        """
        url = f"{self._ntfy_url.rstrip('/')}/{self._ntfy_topic}"
        headers: dict[str, str] = {
            "X-Title": title[:_NTFY_TITLE_MAX],
            "X-Priority": priority,
            "Content-Type": "text/plain; charset=utf-8",
        }
        if self._ntfy_token:
            headers["Authorization"] = f"Bearer {self._ntfy_token}"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, content=body[:_NTFY_BODY_MAX].encode("utf-8"), headers=headers)
                resp.raise_for_status()
                return AlertResult(
                    channel=AlertChannel.NTFY,
                    success=True,
                    message_id=resp.headers.get("X-Message-Id", ""),
                )
        except httpx.HTTPStatusError as exc:
            return AlertResult(channel=AlertChannel.NTFY, success=False, error=str(exc))
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            return AlertResult(channel=AlertChannel.NTFY, success=False, error=f"ntfy unreachable: {exc}")

    def _send_ntfy_sync(self, title: str, body: str, priority: str) -> AlertResult:
        """Version synchrone de _send_ntfy pour les contextes non-async."""
        import urllib.request as _req
        url = f"{self._ntfy_url.rstrip('/')}/{self._ntfy_topic}"
        headers: dict[str, str] = {
            "X-Title": title[:_NTFY_TITLE_MAX],
            "X-Priority": priority,
            "Content-Type": "text/plain; charset=utf-8",
        }
        if self._ntfy_token:
            headers["Authorization"] = f"Bearer {self._ntfy_token}"
        try:
            request = _req.Request(url, data=body[:_NTFY_BODY_MAX].encode("utf-8"), headers=headers, method="POST")
            with _req.urlopen(request, timeout=10) as resp:  # noqa: S310  # nosec B310
                return AlertResult(channel=AlertChannel.NTFY, success=resp.status in (200, 201, 202))
        except Exception as exc:
            return AlertResult(channel=AlertChannel.NTFY, success=False, error=str(exc))

    # ─── Email SMTP ───────────────────────────────────────────────────────────

    async def _send_email(self, subject: str, body: str) -> AlertResult:
        """Envoie un email (async wrapper sur smtplib via executor).

        Args:
            subject: Objet de l'email.
            body: Corps texte brut.

        Returns:
            :class:`AlertResult`.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._send_email_sync, subject, body)

    def _send_email_sync(self, subject: str, body: str) -> AlertResult:
        """Envoi SMTP synchrone avec STARTTLS.

        Args:
            subject: Objet de l'email.
            body: Corps texte brut.

        Returns:
            :class:`AlertResult`.
        """
        if not self._smtp_host:
            return AlertResult(channel=AlertChannel.EMAIL, success=False, error="SMTP_HOST non configuré")
        if not self._smtp_to:
            return AlertResult(channel=AlertChannel.EMAIL, success=False, error="ALERT_EMAIL_TO non configuré")

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self._smtp_from or self._smtp_user
        msg["To"] = ", ".join(self._smtp_to)
        msg.set_content(body)

        try:
            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=15) as smtp:
                if self._smtp_use_tls:
                    smtp.starttls()
                if self._smtp_user and self._smtp_password:
                    smtp.login(self._smtp_user, self._smtp_password)
                smtp.send_message(msg)
            return AlertResult(channel=AlertChannel.EMAIL, success=True)
        except smtplib.SMTPAuthenticationError as exc:
            return AlertResult(channel=AlertChannel.EMAIL, success=False, error=f"Auth SMTP: {exc}")
        except (smtplib.SMTPException, OSError) as exc:
            return AlertResult(channel=AlertChannel.EMAIL, success=False, error=str(exc))

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _is_rate_limited(self, technique: str) -> bool:
        """Vérifie si la technique est en cooldown."""
        last = self._rate_limit.get(technique, 0.0)
        return (time.time() - last) < _RATE_LIMIT_SECONDS

    @staticmethod
    def _ntfy_priority(confidence: float) -> str:
        """Mappe un score de confiance vers la priorité ntfy."""
        if confidence > 0.8:
            return "urgent"
        if confidence > 0.5:
            return "high"
        return "default"

    @staticmethod
    def _build_alert_body(payload: dict[str, Any]) -> tuple[str, str]:
        """Construit le titre et le corps de l'alerte (sans données brutes).

        Args:
            payload: Dict d'alerte (verdict, confidence, technique, narrative, ts).

        Returns:
            Tuple ``(title, body)``.
        """
        technique = payload.get("technique", "UNKNOWN")
        verdict = payload.get("verdict", "UNKNOWN")
        confidence = float(payload.get("confidence", 0.0))
        narrative = str(payload.get("narrative", ""))[:100]

        title = f"\U0001f6a8 SIEM Alert \u2014 {technique}"
        body = (
            f"{verdict} | confidence: {confidence:.0%} | {narrative}\n"
            f"Technique: {technique} | ts: {payload.get('ts', '')}"
        )
        return title, body
