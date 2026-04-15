"""
Intégrité des logs par signature HMAC-SHA256 — NIS2 Art.21.2.h.

Ce module est le pendant du package ``core/`` pour les fonctions d'intégrité
exposées aux nouveaux modules (détecteurs, collecteurs réseau, notificateurs).
Il réexporte et étend les primitives de ``src/collectors/integrity.py`` avec :

- Signature de flux en mémoire (logs réseau, événements Sysmon).
- Chaîne d'intégrité continue (hash précédent inclus dans le suivant).
- Vérification d'intégrité sans accès disque (pour les pipelines en mémoire).

Conformité ANSSI NIS2 Art.21.2.h :
    « Les entités essentielles et importantes mettent en œuvre des mesures
    appropriées pour garantir l'intégrité des données journalisées. »

Référence : Guide ANSSI Journalisation 2022, §3.4 — Intégrité des archives.

Variables d'environnement :
    HMAC_SECRET_KEY  Clé secrète HMAC (minimum 32 octets, base64 recommandé).

Usage typique ::

    chain = LogIntegrityChain(secret_key=b"...")
    sig = chain.sign_event({"timestamp": ..., "message": ...})
    is_valid = chain.verify_event({"timestamp": ..., "message": ...}, sig)
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SignedLogEvent:
    """Événement de log signé avec sa signature HMAC et le hash de chaîne.

    Attributes:
        payload: Contenu brut de l'événement (dict sérialisable en JSON).
        signature: Signature HMAC-SHA256 hexadécimale du payload.
        chain_hash: Hash SHA-256 incluant la signature précédente (chaîne).
        sequence: Numéro de séquence dans la chaîne d'intégrité.
    """

    payload: dict[str, Any]
    signature: str
    chain_hash: str
    sequence: int


class LogIntegrityChain:
    """Chaîne d'intégrité pour séquences d'événements en mémoire.

    Maintient un état de chaîne (hash précédent) pour détecter toute
    insertion ou suppression d'événements dans la séquence.

    Args:
        secret_key: Clé HMAC en bytes (minimum 32 octets recommandé).

    Raises:
        ValueError: Si ``secret_key`` est vide.
    """

    def __init__(self, secret_key: bytes) -> None:
        ...

    def sign_event(self, payload: dict[str, Any]) -> SignedLogEvent:
        """Signe un événement et l'intègre dans la chaîne.

        Args:
            payload: Dictionnaire de l'événement à signer.
                     Doit être sérialisable en JSON (pas de types Python
                     non standards).

        Returns:
            :class:`SignedLogEvent` avec signature et hash de chaîne.

        Raises:
            TypeError: Si ``payload`` contient des valeurs non sérialisables.
        """
        ...

    def verify_event(self, event: SignedLogEvent) -> bool:
        """Vérifie l'intégrité d'un événement signé.

        Contrôle à la fois la signature HMAC du payload et la cohérence
        du hash de chaîne (détection d'insertion/suppression).

        Args:
            event: :class:`SignedLogEvent` à vérifier.

        Returns:
            ``True`` si la signature et le hash de chaîne sont valides.
        """
        ...

    def verify_chain(self, events: list[SignedLogEvent]) -> dict[int, bool]:
        """Vérifie l'intégrité de toute une séquence d'événements.

        Args:
            events: Liste ordonnée de :class:`SignedLogEvent`.

        Returns:
            Dict ``{sequence: is_valid}`` pour chaque événement.
        """
        ...


def hmac_sha256(key: bytes, data: bytes) -> str:
    """Calcule HMAC-SHA256 et retourne la signature hexadécimale.

    Fonction utilitaire bas niveau, exposée pour les tests unitaires.

    Args:
        key: Clé secrète HMAC.
        data: Données à signer.

    Returns:
        Signature hexadécimale HMAC-SHA256.

    Raises:
        ValueError: Si ``key`` est vide.
    """
    if not key:
        raise ValueError("La clé HMAC ne peut pas être vide.")
    return hmac.new(key, data, digestmod=hashlib.sha256).hexdigest()


def constant_time_compare(a: str, b: str) -> bool:
    """Comparaison en temps constant de deux signatures HMAC.

    Protège contre les attaques par timing side-channel.

    Args:
        a: Première signature hexadécimale.
        b: Deuxième signature hexadécimale.

    Returns:
        ``True`` si les deux signatures sont identiques.
    """
    return hmac.compare_digest(a, b)
