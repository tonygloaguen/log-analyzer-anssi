"""
Intégrité des logs par signature HMAC-SHA256 — NIS2 Art.21.2.h.

Expose deux API :
- Fonctions module-level ``sign_event`` / ``verify_event`` :
  usage direct dans tous les modules sans instanciation.
- Classe ``LogIntegrityChain`` :
  chaîne continue pour détecter insertions/suppressions en mémoire.

Variables d'environnement :
    HMAC_SECRET  Clé secrète HMAC (obligatoire, pas de valeur par défaut).
                 Minimum 32 octets, base64 recommandé.
                 Générer : ``openssl rand -base64 48``

Référence : Guide ANSSI Journalisation 2022, §3.4 — Intégrité des archives.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac_mod
import json
import os
from dataclasses import dataclass
from typing import Any


# ─── Helpers internes ────────────────────────────────────────────────────────

def _require_secret() -> bytes:
    """Lit HMAC_SECRET depuis l'environnement (obligatoire).

    Returns:
        Clé HMAC encodée en bytes.

    Raises:
        RuntimeError: Si HMAC_SECRET n'est pas définie ou est vide.
    """
    val = os.environ.get("HMAC_SECRET", "")
    if not val:
        raise RuntimeError(
            "La variable d'environnement HMAC_SECRET est obligatoire et non définie. "
            "Générer avec : openssl rand -base64 48"
        )
    return val.encode("utf-8")


def _canonical_bytes(event: dict[str, Any]) -> bytes:
    """Sérialise un dict en JSON canonique (sort_keys, compact) en bytes.

    Args:
        event: Dictionnaire à sérialiser.

    Returns:
        Représentation bytes déterministe du dict.

    Raises:
        TypeError: Si une valeur du dict n'est pas sérialisable en JSON.
    """
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _hmac_sha256_bytes(key: bytes, data: bytes) -> str:
    """Calcule HMAC-SHA256 sur des bytes bruts.

    Args:
        key: Clé secrète HMAC (non vide).
        data: Données à signer.

    Returns:
        Signature hexadécimale (64 caractères).
    """
    return _hmac_mod.new(key, data, digestmod=hashlib.sha256).hexdigest()


# ─── API module-level (utilisée par tous les modules) ────────────────────────

def sign_event(event: dict[str, Any], secret: bytes) -> str:
    """Signe un événement dict avec HMAC-SHA256.

    La sérialisation JSON utilise ``sort_keys=True`` pour garantir
    un résultat déterministe quel que soit l'ordre des clés.

    Args:
        event: Dictionnaire de l'événement à signer.
               Toutes les valeurs doivent être sérialisables JSON.
        secret: Clé HMAC en bytes (non vide).

    Returns:
        Signature hexadécimale HMAC-SHA256 (64 caractères).

    Raises:
        ValueError: Si ``secret`` est vide.
        TypeError: Si ``event`` contient des valeurs non sérialisables.
    """
    if not secret:
        raise ValueError("La clé HMAC ne peut pas être vide.")
    return _hmac_sha256_bytes(secret, _canonical_bytes(event))


def verify_event(event: dict[str, Any], signature: str, secret: bytes) -> bool:
    """Vérifie la signature HMAC-SHA256 d'un événement.

    Utilise une comparaison en temps constant pour prévenir les attaques
    par timing side-channel (ANSSI).

    Args:
        event: Dictionnaire de l'événement original.
        signature: Signature hexadécimale attendue.
        secret: Clé HMAC en bytes.

    Returns:
        ``True`` si la signature est valide, ``False`` sinon.
    """
    if not secret:
        return False
    expected = sign_event(event, secret)
    return _hmac_mod.compare_digest(expected, signature)


# ─── Classe LogIntegrityChain ─────────────────────────────────────────────────

@dataclass
class SignedLogEvent:
    """Événement signé avec sa signature HMAC et le hash de chaîne.

    Attributes:
        payload: Contenu brut de l'événement (dict JSON-sérialisable).
        signature: Signature HMAC-SHA256 hexadécimale du payload.
        chain_hash: SHA-256 de ``(signature + prev_chain_hash)`` — détecte
            toute insertion ou suppression dans la séquence.
        sequence: Numéro de séquence (commence à 1).
    """

    payload: dict[str, Any]
    signature: str
    chain_hash: str
    sequence: int


class LogIntegrityChain:
    """Chaîne d'intégrité pour séquences d'événements en mémoire.

    Chaque événement signé inclut le hash du précédent, formant une chaîne
    dont toute rupture (insertion, suppression, modification) est détectable.

    Args:
        secret_key: Clé HMAC en bytes (minimum 32 octets recommandé).

    Raises:
        ValueError: Si ``secret_key`` est vide.

    Example::

        chain = LogIntegrityChain(secret_key=b"ma-cle-secrete-32-octets-minimum")
        ev = chain.sign_event({"ts": 1710461862.0, "msg": "driver loaded"})
        assert chain.verify_event(ev)
    """

    def __init__(self, secret_key: bytes) -> None:
        if not secret_key:
            raise ValueError("secret_key ne peut pas être vide.")
        self._key = secret_key
        self._prev_chain_hash: str = ""
        self._seq: int = 0

    def sign_event(self, payload: dict[str, Any]) -> SignedLogEvent:
        """Signe un événement et l'intègre dans la chaîne.

        Args:
            payload: Dict de l'événement (valeurs JSON-sérialisables).

        Returns:
            :class:`SignedLogEvent` avec signature et hash de chaîne.

        Raises:
            TypeError: Si ``payload`` contient des valeurs non sérialisables.
        """
        sig = _hmac_sha256_bytes(self._key, _canonical_bytes(payload))
        # chain_hash = sha256(sig_hex + prev_chain_hash)
        chain_input = (sig + self._prev_chain_hash).encode("utf-8")
        chain_hash = hashlib.sha256(chain_input).hexdigest()
        self._prev_chain_hash = chain_hash
        self._seq += 1
        return SignedLogEvent(
            payload=payload,
            signature=sig,
            chain_hash=chain_hash,
            sequence=self._seq,
        )

    def verify_event(self, event: SignedLogEvent) -> bool:
        """Vérifie la signature HMAC du payload d'un événement (sans contexte de chaîne).

        Pour la vérification complète incluant la continuité de la chaîne,
        utiliser :meth:`verify_chain`.

        Args:
            event: :class:`SignedLogEvent` à vérifier.

        Returns:
            ``True`` si la signature HMAC du payload est valide.
        """
        expected = _hmac_sha256_bytes(self._key, _canonical_bytes(event.payload))
        return _hmac_mod.compare_digest(expected, event.signature)

    def verify_chain(self, events: list[SignedLogEvent]) -> dict[int, bool]:
        """Vérifie l'intégrité complète d'une séquence d'événements signés.

        Contrôle pour chaque événement :
        1. La signature HMAC du payload.
        2. La cohérence du hash de chaîne avec l'événement précédent.

        Args:
            events: Liste ordonnée de :class:`SignedLogEvent`.

        Returns:
            Dict ``{sequence: is_valid}`` pour chaque événement.
        """
        results: dict[int, bool] = {}
        prev_chain = ""
        for ev in events:
            sig_ok = self.verify_event(ev)
            chain_input = (ev.signature + prev_chain).encode("utf-8")
            expected_chain = hashlib.sha256(chain_input).hexdigest()
            chain_ok = _hmac_mod.compare_digest(expected_chain, ev.chain_hash)
            results[ev.sequence] = sig_ok and chain_ok
            prev_chain = ev.chain_hash
        return results


# ─── Utilitaires bas niveau (exposés pour les tests) ─────────────────────────

def hmac_sha256(key: bytes, data: bytes) -> str:
    """Calcule HMAC-SHA256 sur des bytes bruts.

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
    return _hmac_sha256_bytes(key, data)


def constant_time_compare(a: str, b: str) -> bool:
    """Comparaison en temps constant de deux chaînes hexadécimales.

    Protège contre les attaques par timing side-channel.

    Args:
        a: Première signature hexadécimale.
        b: Deuxième signature hexadécimale.

    Returns:
        ``True`` si les deux signatures sont identiques.
    """
    return _hmac_mod.compare_digest(a, b)
