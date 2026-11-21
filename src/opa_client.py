from typing import Dict, List, Tuple
import requests
from src.models import Document, User

class OPAClient:
    """Evaluates authorization decisions against an Open Policy Agent sidecar/service."""
    
    def __init__(self, opa_url: str = "http://localhost:8181/v1/data/defense/llm/authz"):
        self.opa_url = opa_url
        self.session = requests.Session()

    def evaluate_retrieval(self, user: User, doc: Document, recent_activity: List[Dict]) -> Tuple[bool, List[str]]:
        accumulated_entities = set()
        recent_doc_ids = []
        for record in recent_activity:
            accumulated_entities.update(record["entities"])
            recent_doc_ids.append(record["doc_id"])

        opa_input = {
            "input": {
                "user": {
                    "user_id": user.user_id,
                    "role": user.role,
                    "clearance": user.clearance,
                    "compartments": list(user.compartments),
                },
                "document": {
                    "doc_id": doc.doc_id,
                    "classification": doc.classification,
                    "compartment": doc.compartment,
                    "entities": list(doc.entities),
                },
                "session": {
                    "recent_docs": recent_doc_ids,
                    "accumulated_entities": list(accumulated_entities),
                },
                "config": {
                    "max_docs_per_hour": 3,
                    "forbidden_combinations": [
                        ["ALPHA_COORDS", "ALPHA_SCHEDULE"]
                    ]
                }
            }
        }

        try:
            resp = self.session.post(self.opa_url, json=opa_input, timeout=0.5)
            resp.raise_for_status()
            result = resp.json().get("result", {})
            return result.get("allow", False), result.get("deny_reasons", [])
        except requests.RequestException as e:
            return False, [f"OPA Policy Engine unreachable (Fail-Closed): {e}"]
