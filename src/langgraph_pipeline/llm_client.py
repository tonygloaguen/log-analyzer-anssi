"""
Client LLM local via Ollama (Mistral 7B).

Conforme ANSSI : aucune donnée n'est envoyée vers un service externe.
Le modèle tourne entièrement en local dans le conteneur Ollama.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """Tu es un expert en sécurité informatique et analyse de logs.
Tu analyses des logs de sécurité conformément aux recommandations ANSSI.
Réponds toujours en français, de manière concise et structurée.
Ne révèle jamais de données personnelles ou sensibles dans tes réponses.
Concentre-toi sur les indicateurs de compromission (IoC) et les anomalies.
"""


class OllamaClient:
    """Client asynchrone pour l'API Ollama locale."""

    def __init__(
        self,
        base_url: str = "http://ollama:11434",
        model: str = "mistral:7b-instruct",
        timeout: float = 120.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    async def generate(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.1,
    ) -> str:
        """
        Génère une réponse du LLM local.

        Args:
            prompt: Le message utilisateur à envoyer au modèle.
            system: Prompt système (remplace le prompt par défaut si fourni).
            temperature: Température de génération (bas = déterministe).

        Returns:
            La réponse textuelle du modèle.
        """
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "system": system or SYSTEM_PROMPT,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": 1024,
            },
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
                return data.get("response", "").strip()

            except httpx.TimeoutException:
                logger.error("Timeout lors de l'appel Ollama (model=%s)", self.model)
                return "[ERREUR] Timeout LLM — analyse manuelle requise."
            except httpx.HTTPStatusError as e:
                logger.error("Erreur HTTP Ollama: %s", e)
                return f"[ERREUR] Service LLM indisponible: {e.response.status_code}"
            except Exception as e:
                logger.error("Erreur inattendue Ollama: %s", e)
                return "[ERREUR] Analyse LLM impossible — vérifier le service Ollama."

    async def analyze_anomalies(
        self,
        log_summary: str,
        anomaly_descriptions: list[str],
    ) -> tuple[str, list[str]]:
        """
        Analyse contextuelle des anomalies détectées.

        Returns:
            Tuple (analyse_textuelle, liste_recommandations)
        """
        anomalies_text = "\n".join(f"- {a}" for a in anomaly_descriptions)
        prompt = f"""Analyse les anomalies suivantes détectées dans les logs de sécurité :

RÉSUMÉ DES LOGS :
{log_summary}

ANOMALIES DÉTECTÉES :
{anomalies_text}

Fournis :
1. Une analyse de la situation (2-3 phrases)
2. Une liste de 3 à 5 recommandations concrètes numérotées
3. Le niveau de risque global (FAIBLE / MODÉRÉ / ÉLEVÉ / CRITIQUE)

Format de réponse :
ANALYSE: <analyse>
RECOMMANDATIONS:
1. <recommandation 1>
2. <recommandation 2>
...
RISQUE: <niveau>
"""
        response = await self.generate(prompt)
        return self._parse_llm_response(response)

    def _parse_llm_response(self, response: str) -> tuple[str, list[str]]:
        """Parse la réponse structurée du LLM."""
        analysis = ""
        recommendations: list[str] = []

        lines = response.split("\n")
        current_section = None

        for line in lines:
            line = line.strip()
            if line.startswith("ANALYSE:"):
                current_section = "analysis"
                analysis = line[8:].strip()
            elif line.startswith("RECOMMANDATIONS:"):
                current_section = "recommendations"
            elif line.startswith("RISQUE:"):
                current_section = None
            elif current_section == "analysis" and line:
                analysis += " " + line
            elif current_section == "recommendations" and line and line[0].isdigit():
                rec = line.split(".", 1)[-1].strip()
                if rec:
                    recommendations.append(rec)

        if not analysis:
            analysis = response[:500]  # Fallback : prendre le début de la réponse

        return analysis.strip(), recommendations

    async def is_available(self) -> bool:
        """Vérifie que le service Ollama est disponible et le modèle chargé."""
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                resp = await client.get(f"{self.base_url}/api/version")
                return resp.status_code == 200
            except Exception:
                return False
