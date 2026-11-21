from dataclasses import dataclass
from typing import Dict, Set

@dataclass
class User:
    user_id: str
    role: str
    clearance: int  # 1: Unclassified, 2: Secret, 3: Top Secret
    compartments: Set[str]

@dataclass
class Document:
    doc_id: str
    title: str
    classification: int
    compartment: str
    entities: Set[str]
    raw_content: str

DOCUMENT_STORE: Dict[str, Document] = {
    "DOC-101": Document(
        doc_id="DOC-101",
        title="Base Alpha Perimeter Coordinates",
        classification=2,
        compartment="FACILITY_ALPHA",
        entities={"ALPHA_COORDS"},
        raw_content="Base Alpha is located at 34.0522 N, 118.2437 W. Perimeter fence is 4m high."
    ),
    "DOC-102": Document(
        doc_id="DOC-102",
        title="Base Alpha Guard Shift Schedule",
        classification=2,
        compartment="FACILITY_ALPHA",
        entities={"ALPHA_SCHEDULE"},
        raw_content="Guard rotation occurs at 0600, 1400, and 2200 hours. North gate has 2 personnel."
    ),
    "DOC-103": Document(
        doc_id="DOC-103",
        title="Project Valkyrie Guidance Specs",
        classification=3,
        compartment="WEAPON_VALKYRIE",
        entities={"VALKYRIE_SPECS"},
        raw_content="Valkyrie warhead uses dual-stage inertial guidance with 0.5m CEP."
    ),
}
