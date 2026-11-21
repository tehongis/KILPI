from typing import Set
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer

class AutomatedEntityTagger:
    """Extracts Mosaic Effect entities from raw documents offline during ingestion."""

    def __init__(self):
        self.analyzer = AnalyzerEngine()

        # Custom Recognizer 1: Geographic Coordinates
        coord_pattern = Pattern(
            name="gps_coords",
            regex=r"\b\d{1,3}\.\d+\s*[NS],\s*\d{1,3}\.\d+\s*[EW]\b",
            score=0.95,
        )
        self.analyzer.registry.add_recognizer(
            PatternRecognizer(supported_entity="GEO_COORDINATES", patterns=[coord_pattern])
        )

        # Custom Recognizer 2: Guard Shifts / Operational Timetables
        schedule_pattern = Pattern(
            name="military_schedule",
            regex=r"\b([01]\d|2[0-3])[0-5]\d\s*(hours|hrs|zulu)\b",
            score=0.90,
        )
        self.analyzer.registry.add_recognizer(
            PatternRecognizer(supported_entity="OPERATIONAL_SCHEDULE", patterns=[schedule_pattern])
        )

    def extract_entities(self, text: str, compartment: str) -> Set[str]:
        """Returns normalized, compartment-scoped entity tags (e.g., FACILITY_ALPHA:GEO_COORDINATES)."""
        results = self.analyzer.analyze(
            text=text,
            entities=["GEO_COORDINATES", "OPERATIONAL_SCHEDULE", "LOCATION", "ORGANIZATION"],
            language="en",
        )
        tags = set()
        for res in results:
            if res.score >= 0.75:
                # Scope extracted entity to the document's compartment for precise Mosaic rules
                tags.add(f"{compartment}:{res.entity_type}")
        return tags
