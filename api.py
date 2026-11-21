import os
from typing import List
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel

from src.auth import get_authenticated_user
from src.models import User
from src.opa_client import OPAClient
from src.output_guard import OutputGuard
from src.policy_engine import PolicyEngine
from src.tracker import ValkeySessionTracker
from src.vector_store import QdrantRetriever

app = FastAPI(title="Defense LLM Policy & Guardrail Proxy", version="1.0.0")

tracker = ValkeySessionTracker(
    host=os.getenv("VALKEY_HOST", "valkey"),
    port=int(os.getenv("VALKEY_PORT", "6379")),
    use_tls=os.getenv("VALKEY_TLS", "true").lower() == "true",
    cert_dir=os.getenv("CERT_DIR", "/certs"),
)
opa = OPAClient(opa_url=os.getenv("OPA_URL", "http://opa:8181/v1/data/defense/llm/authz"))
retriever = QdrantRetriever(host=os.getenv("QDRANT_HOST", "qdrant"), port=6333)
engine = PolicyEngine(tracker, opa)
out_guard = OutputGuard()

class QueryRequest(BaseModel):
    prompt: str
    top_k: int = 5

class RetrievedDocResponse(BaseModel):
    doc_id: str
    title: str
    content: str
    redacted: bool

class QueryResponse(BaseModel):
    status: str
    documents: List[RetrievedDocResponse]
    audit_logs: List[str]

@app.post("/v1/retrieve", response_model=QueryResponse)
def retrieve_documents(req: QueryRequest, user: User = Depends(get_authenticated_user)):
    # 1. Gate 1: Input Guardrails
    allowed, msg = engine.gate_1_pre_retrieval(user, req.prompt)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=msg)

    # 2. Semantic Vector Retrieval (with DB-level ABAC pre-filtering)
    candidate_docs = retriever.search(req.prompt, user=user, top_k=req.top_k)

    # 3. Gate 2: OPA + Valkey Stateful Policy (Mosaic Effect & Rate Limits) + Watermarking
    approved_docs, audit_logs = engine.gate_2_post_retrieval(user, candidate_docs)

    # 4. Output DLP Sanitization
    final_docs = []
    for d in approved_docs:
        clean_text, was_redacted = out_guard.sanitize_document(req.prompt, d.raw_content)
        final_docs.append(
            RetrievedDocResponse(
                doc_id=d.doc_id,
                title=d.title,
                content=clean_text,
                redacted=was_redacted
            )
        )

    return QueryResponse(
        status="success",
        documents=final_docs,
        audit_logs=audit_logs
    )
