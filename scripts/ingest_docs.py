import os
from src.models import DOCUMENT_STORE
from src.entity_tagger import AutomatedEntityTagger
from src.vector_store import QdrantRetriever

if __name__ == "__main__":
    retriever = QdrantRetriever(
        host=os.getenv("QDRANT_HOST", "localhost"),
        port=int(os.getenv("QDRANT_PORT", "6333")),
        api_key=os.getenv("QDRANT_API_KEY"),
        use_tls=os.getenv("QDRANT_TLS", "true").lower() == "true",
        ca_cert_path=os.path.join(os.getenv("CERT_DIR", "/certs"), "ca.crt"),
    )
    tagger = AutomatedEntityTagger()

    docs = list(DOCUMENT_STORE.values())
    for doc in docs:
        auto_tags = tagger.extract_entities(doc.raw_content, doc.compartment)
        doc.entities.update(auto_tags)
        print(f"[TAGGER] {doc.doc_id} tagged with entities: {doc.entities}")

    retriever.index_documents(docs)
    print(f"[INGEST] Indexed {len(docs)} documents into Qdrant over TLS.")
