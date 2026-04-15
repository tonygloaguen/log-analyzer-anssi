"""
Dispatcher d'alertes — ntfy (canal principal) + email SMTP (fallback).

Envoie des notifications d'incidents en temps réel lorsque le pipeline
LangGraph produit un rapport avec score de risque ≥ seuil configuré.

Canaux :
    1. **ntfy** (push HTTP) : léger, auto-hébergeable, sans compte requis.
    2. **Email SMTP** : fallback activé si ntfy est indisponible ou si la
       sévérité est ``CRITICAL``.

Conformité ANSSI :
    - Aucune donnée de log brute dans les notifications (résumé uniquement).
    - TLS obligatoire sur le canal SMTP (``SMTP_USE_TLS=true``).
    - Traçabilité des alertes envoyées dans la table ``audit_trail``.

Variables d'environnement :
    NTFY_URL           URL ntfy (ex. ``https://ntfy.sh/mon-topic``).
    NTFY_TOKEN         Token d'authentification ntfy (optionnel).
    SMTP_HOST          Serveur SMTP (ex. ``smtp.example.com``).
    SMTP_PORT          Port SMTP (défaut ``587``).
    SMTP_USER          Identifiant SMTP.
    SMTP_PASSWORD      Mot de passe SMTP.
    SMTP_FROM          Adresse expéditeur.
    SMTP_TO            Adresse(s) destinataire(s), séparées par des virgules.
    SMTP_USE_TLS       Activer STARTTLS (défaut ``true``).
    ALERT_MIN_SCORE    Score minimal pour déclencher une alerte (défaut ``0.6``).

Usage typique ::

    dispatcher = AlertDispatcher()
    await dispatcher.dispatch(report)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AlertChannel(str, Enum):
    """Canal de notification utilisé pour l'envoi de l'alerte."""

    NTFY = "ntfy"
    EMAIL = "email"
    NONE = "none"


@dataclass
class AlertResult:
    """Résultat d'une tentative d'envoi d'alerte.

    Attributes:
        channel: Canal effectivement utilisé.
        success: ``True`` si l'alerte a bien été envoyée.
        message_id: Identifiant de message retourné par le canal (si disponible).
        error: Message d'erreur en cas d'échec.
    """

    channel: AlertChannel
    success: bool
    message_id: str = ""
    error: str = ""


class AlertDispatcher:
    """Dispatcher d'alertes multi-canal avec stratégie de fallback.

    Tente ntfy en premier ; si indisponible ou si sévérité == CRITICAL,
    envoie également un email SMTP.

    Args:
        ntfy_url: URL du topic ntfy cible.
        ntfy_token: Token d'authentification ntfy (``None`` si public).
        smtp_host: Hôte SMTP pour le fallback email.
        smtp_port: Port SMTP (587 pour STARTTLS).
        smtp_user: Identifiant SMTP.
        smtp_password: Mot de passe SMTP.
        smtp_from: Adresse expéditeur.
        smtp_to: Liste des destinataires.
        smtp_use_tls: Activer STARTTLS (fortement recommandé).
        alert_min_score: Score minimal pour déclencher une alerte.
    """

    def __init__(
        self,
        ntfy_url: str = "",
        ntfy_token: str | None = None,
        smtp_host: str = "",
        smtp_port: int = 587,
        smtp_user: str = "",
        smtp_password: str = "",
        smtp_from: str = "",
        smtp_to: list[str] | None = None,
        smtp_use_tls: bool = True,
        alert_min_score: float = 0.6,
    ) -> None:
        ...

    async def dispatch(self, report: object) -> AlertResult:
        """Envoie une alerte pour le rapport donné.

        Sélectionne automatiquement le canal en fonction de la disponibilité
        de ntfy et de la sévérité du rapport.

        Args:
            report: :class:`src.models.report.AnalysisReport` produit par le pipeline.

        Returns:
            :class:`AlertResult` décrivant le résultat de l'envoi.
        """
        ...

    async def _send_ntfy(self, title: str, body: str, priority: str) -> AlertResult:
        """Envoie une notification push via ntfy.

        Args:
            title: Titre de la notification (max 256 caractères).
            body: Corps de la notification (résumé de l'incident).
            priority: Priorité ntfy (``default``, ``high``, ``urgent``).

        Returns:
            :class:`AlertResult` avec le statut de l'envoi.
        """
        ...

    async def _send_email(self, subject: str, body: str) -> AlertResult:
        """Envoie un email via SMTP avec STARTTLS.

        Args:
            subject: Objet de l'email.
            body: Corps de l'email (texte brut, sans données sensibles).

        Returns:
            :class:`AlertResult` avec le statut de l'envoi.

        Raises:
            ValueError: Si les paramètres SMTP sont incomplets.
        """
        ...

    @staticmethod
    def _build_alert_body(report: object) -> tuple[str, str]:
        """Construit le titre et le corps de l'alerte depuis un rapport.

        Aucune donnée de log brute n'est incluse (conformité ANSSI).

        Args:
            report: :class:`src.models.report.AnalysisReport`.

        Returns:
            Tuple ``(title, body)`` prêt à l'envoi.
        """
        ...
