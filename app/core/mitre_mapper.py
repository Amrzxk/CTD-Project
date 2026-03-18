"""
Maps ML attack categories to MITRE ATT&CK tactics and techniques.

Loaded once at startup from a static JSON knowledge base.
Only applies mapping when model confidence meets the configured threshold.
"""
import json
from pathlib import Path
from typing import Optional


class MitreMapper:

    def __init__(self, mapping_path: Path):
        raw = json.loads(mapping_path.read_text(encoding="utf-8"))
        self._version: str = raw.get("version", "1.0")
        self._framework: str = raw.get("framework", "MITRE ATT&CK")
        self._min_confidence: float = raw.get("min_confidence", 0.70)
        self._bands: dict = raw.get("confidence_bands", {})
        self._mappings: dict = raw.get("mappings", {})

    @property
    def min_confidence(self) -> float:
        return self._min_confidence

    @property
    def categories(self) -> list[str]:
        return list(self._mappings.keys())

    def lookup(self, attack_category: str) -> Optional[dict]:
        """Return the full MITRE mapping for a single attack category, or None."""
        return self._mappings.get(attack_category)

    def get_matrix(self) -> dict:
        """Return the complete matrix payload for the frontend."""
        matrix_entries = []
        for category, data in self._mappings.items():
            matrix_entries.append({
                "category": category,
                "description": data.get("description", ""),
                "tactics": data.get("tactics", []),
            })

        return {
            "version": self._version,
            "framework": self._framework,
            "min_confidence": self._min_confidence,
            "confidence_bands": self._bands,
            "entries": matrix_entries,
        }

    def enrich_prediction(self, prediction: dict) -> dict:
        """
        Return a new dict with MITRE fields added.

        If the prediction is Normal, below the confidence threshold,
        or the attack category is unknown, `mitre` will be None.
        """
        enriched = {**prediction}

        if prediction.get("prediction") != "Malicious":
            enriched["mitre"] = None
            return enriched

        confidence = prediction.get("confidence", 0.0)
        if confidence < self._min_confidence:
            enriched["mitre"] = None
            return enriched

        attack_type = prediction.get("attack_type")
        mapping = self._mappings.get(attack_type) if attack_type else None
        if not mapping:
            enriched["mitre"] = None
            return enriched

        tactics = []
        techniques = []
        for tactic in mapping.get("tactics", []):
            tactics.append({"id": tactic["id"], "name": tactic["name"]})
            for tech in tactic.get("techniques", []):
                techniques.append({
                    "id": tech["id"],
                    "name": tech["name"],
                    "url": tech.get("url", ""),
                })

        enriched["mitre"] = {
            "confidence_band": self._resolve_band(confidence),
            "tactics": tactics,
            "techniques": techniques,
        }
        return enriched

    def _resolve_band(self, confidence: float) -> str:
        for band_key, band in self._bands.items():
            if band["min"] <= confidence < band["max"]:
                return band_key
        if confidence >= 0.95:
            return "very_high"
        return "low"
