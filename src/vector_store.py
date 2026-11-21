import os
from typing import List
from fastembed import TextEmbedding
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    FieldCondition,
    Filter,
    MatchAny,
    PointStruct,
    Range,
    VectorParams,
)
from src.models import Document, User

COLLECTION_NAME = "classified_documents"
EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"

class QdrantRetriever:
    """Self-hosted Qdrant vector store over TLS + API Key with DB-level ABAC pre-filtering."""

    def __init__(
        self,
        host: str = None,
        port: int = 6333,
        api_key: str = None,
        use_tls: bool = True,
        ca_cert_path: str = "/certs/ca.crt",
    ):
        host = host or os.getenv("QDRANT_HOST", "qdrant")
        api_key = api_key or os.getenv("QDRANT_API_KEY")
        protocol = "https" if use_tls else "http"

        self.client = QdrantClient(
            url=f"{protocol}://{host}:{port}",
            api_key=api_key,
            verify=ca_cert_path if use_tls else False,
        )
        self.embedder = TextEmbedding(model_name=EMBEDDING_MODEL)

    def ensure_collection(self):
        if not self.client.collection_exists(COLLECTION_NAME):
            self.client.create_collection(
                collection_name=COLLECTION_NAME,
                vectors_config=VectorParams(size=384, distance=Distance.COSINE),
            )

    def index_documents(self, docs: List[Document]):
        self.ensure_collection()
        texts = [f"{d.title}: {d.raw_content}" for d in docs]
        embeddings = list(self.embedder.embed(texts))

        points = [
            PointStruct(
                id=idx,
                vector=vector.tolist(),
                payload={
                    "doc_id": doc.doc_id,
                    "title": doc.title,
                    "classification": doc.classification,
                    "compartment": doc.compartment,
                    "entities": list(doc.entities),
                    "raw_content": doc.raw_content,
                },
            )
            for idx, (doc, vector) in enumerate(zip(docs, embeddings), start=1)
        ]
        self.client.upsert(collection_name=COLLECTION_NAME, points=points)

    def search(self, query: str, user: User, top_k: int = 5) -> List[Document]:
        if not self.client.collection_exists(COLLECTION_NAME):
            return []

        query_vector = list(self.embedder.embed([query])).tolist()

        abac_filter = Filter(
            must=[
                FieldCondition(key="classification", range=Range(lte=user.clearance)),
                FieldCondition(key="compartment", match=MatchAny(any=list(user.compartments))),
            ]
        )

        hits = self.client.query_points(
            collection_name=COLLECTION_NAME,
            query=query_vector,
            query_filter=abac_filter,
            limit=top_k,
            with_payload=True,
        ).points

        return [
            Document(
                doc_id=h.payload["doc_id"],
                title=h.payload["title"],
                classification=h.payload["classification"],
                compartment=h.payload["compartment"],
                entities=set(h.payload["entities"]),
                raw_content=h.payload["raw_content"],
            )
            for h in hits
        ]
