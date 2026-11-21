from typing import Tuple
from llm_guard import scan_output
from llm_guard.output_scanners import Regex
from llm_guard.output_scanners.regex import MatchType

class OutputGuard:
    """Scans and redacts sensitive patterns in raw retrieved chunks before user display."""

    def __init__(self):
        # Define regex patterns for sensitive defense identifiers to mask automatically
        self.regex_scanner = Regex(
            patterns=[
                # Exact GPS coordinates (e.g., 34.0522 N, 118.2437 W)
                r"\b\d{1,3}\.\d+\s*[NS],\s*\d{1,3}\.\d+\s*[EW]\b",
                # Explicit Top Secret / SCI classification banners
                r"\b(TOP SECRET//SCI|NOFORN|ORCON)\b",
            ],
            match_type=MatchType.ALL,
            redact=True  # Replaces matches with [REDACTED] instead of blocking the whole doc
        )
        self.scanners = [self.regex_scanner]

    def sanitize_document(self, prompt: str, raw_text: str) -> Tuple[str, bool]:
        """Returns (sanitized_text, was_modified)."""
        sanitized_text, results_valid, _ = scan_output(
            self.scanners,
            prompt,
            raw_text
        )
        was_modified = not all(results_valid.values())
        return sanitized_text, was_modified
