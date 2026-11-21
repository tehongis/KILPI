from typing import List, Tuple
from llm_guard import scan_prompt
from llm_guard.input_scanners import BanSubstrings, PromptInjection
from llm_guard.input_scanners.ban_substrings import MatchType

from src.models import Document, User
from src.opa_client import OPAClient
from src.tracker import ValkeySessionTracker

class PolicyEngine:
    def __init__(self, tracker: ValkeySessionTracker, opa: OPAClient):
        self.tracker = tracker
        self.opa = opa

        self.keyword_scanner = BanSubstrings(
            substrings=[
                "system prompt",
                "dump all",
                "base64",
                "export database",
                "bypass clearance",
                "ROOT_OVERRIDE_KEY"
            ],
            match_type=MatchType.STR,
            case_sensitive=False,
            redact=False
        )

        self.injection_scanner = PromptInjection(
            threshold=0.85,
            use_onnx=True
        )

        self.input_scanners = [self.keyword_scanner, self.injection_scanner]

    def gate_1_pre_retrieval(self, user: User, prompt: str) -> Tuple[bool, str]:
        _, results_valid, results_score = scan_prompt(
            self.input_scanners,
            prompt,
            fail_fast=True
        )

        for scanner_name, is_valid in results_valid.items():
            if not is_valid:
                score = results_score.get(scanner_name, 1.0)
                return False, f"BLOCKED [Gate 1 - {scanner_name}]: Violation detected (risk score: {score:.2f})."

        return True, "OK"

    def gate_2_post_retrieval(self, user: User, docs: List[Document]) -> Tuple[List[Document], List[str]]:
        approved_docs = []
        audit_logs = []

        for doc in docs:
            recent_activity = self.tracker.get_recent_activity(user.user_id)
            allowed, deny_reasons = self.opa.evaluate_retrieval(user, doc, recent_activity)

            if not allowed:
                reasons_str = "; ".join(deny_reasons) if deny_reasons else "Policy denied"
                audit_logs.append(f"DENIED [{doc.doc_id}] by OPA: {reasons_str}")
                continue

            self.tracker.log_retrieval(user.user_id, doc)

            watermarked_doc = Document(
                doc_id=doc.doc_id,
                title=doc.title,
                classification=doc.classification,
                compartment=doc.compartment,
                entities=doc.entities,
                raw_content=self._apply_watermark(doc.raw_content, user.user_id)
            )
            approved_docs.append(watermarked_doc)
            audit_logs.append(f"APPROVED [{doc.doc_id}] by OPA: Released to {user.user_id}.")

        return approved_docs, audit_logs

    def _apply_watermark(self, text: str, user_id: str) -> str:
        binary = ''.join(format(ord(c), '08b') for c in user_id)
        zw_watermark = ''.join('\u200b' if b == '1' else '\u200c' for b in binary)
        return f"{text}{zw_watermark}"
