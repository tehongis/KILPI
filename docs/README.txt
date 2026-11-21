================================================================================
DEFENSE LLM GUARDRAIL & POLICY PROXY (HARDENED ZERO-TRUST ARCHITECTURE)
================================================================================

1. OVERVIEW
--------------------------------------------------------------------------------
This project implements a zero-trust, air-gap-ready policy enforcement proxy for
internal defense and high-compliance RAG systems serving raw sensitive documents.

Because authorized military personnel and external contractors legitimately query
operational terms (e.g., weapons, facilities, plans), static keyword blacklists
alone fail to stop insider threats or compromised credentials. Instead, this
system enforces defense-in-depth across six security layers:
  1. Asymmetric JWT/OIDC verification (RS256/ES256) for cryptographic identity
  2. Pre-retrieval adversarial & keyword filtering (ProtectAI LLM Guard)
  3. Database-level ABAC pre-filtering inside Qdrant over TLS + API key auth
  4. Stateful Aggregation Tracking (Valkey + Open Policy Agent) to block
     "Mosaic Effect" intelligence harvesting across separate queries
  5. Output Data Loss Prevention (DLP) pattern redaction prior to rendering
  6. Invisible forensic zero-width Unicode watermarking tied to the user's ID


2. END-TO-END ARCHITECTURE FLOW
--------------------------------------------------------------------------------
[Client Request + Bearer JWT]
     |
     v
+-------------------------------------------------------------------+

| AUTH LAYER: Asymmetric JWT/OIDC Verification (auth.py)            |
|  - Verifies RS256/ES256 signature against pinned IdP public key   |
|  - Extracts verified sub (user_id), clearance, & compartments     |
+-------------------------------------------------------------------+
     | (Verified User Identity)
     v
+-------------------------------------------------------------------+

| GATE 1: Pre-Retrieval Input Guardrails (policy_engine.py)         |
|  1. BanSubstrings: <1ms deterministic keyword/command blocking    |
|  2. PromptInjection: Local DeBERTa-v3 ONNX jailbreak classifier   |
+-------------------------------------------------------------------+
     | (Approved Prompt)
     v
+-------------------------------------------------------------------+

| RETRIEVAL: Self-Hosted Qdrant Vector DB (vector_store.py)         |
|  - Embeds query locally via FastEmbed (BAAI/bge-small-en-v1.5)    |
|  - Connects over HTTPS (TLS) + API Key authentication             |
|  - Enforces DB-level ABAC pre-filter (clearance & compartment)    |
+-------------------------------------------------------------------+
     | (Candidate Raw Documents)
     v
+-------------------------------------------------------------------+

| GATE 2: Stateful Policy & Aggregation (Valkey + OPA)              |
|  1. ValkeySessionTracker: Fetches sliding-window retrieval state  |
|     over mutual TLS (mTLS) + ACL authentication                   |
|  2. OPAClient (policy.rego): Evaluates clearance, compartment,    |
|     hourly rate limits, and forbidden Mosaic entity combinations  |
|  3. Watermarking: Embeds zero-width Unicode user ID into text     |
+-------------------------------------------------------------------+
     | (Authorized Documents)
     v
+-------------------------------------------------------------------+

| OUTPUT DLP: Pattern Sanitization (output_guard.py)                |
|  - Redacts sensitive patterns (e.g., exact GPS coordinates,       |
|    classification banners) before returning JSON response         |
+-------------------------------------------------------------------+
     |
     v
[FastAPI JSON Response -> Read-Only Client Viewer]


3. PROJECT DIRECTORY STRUCTURE
--------------------------------------------------------------------------------
defense_llm_guard/
├── api.py                 - FastAPI REST microservice entrypoint (POST /v1/retrieve)
├── src/                   - Application modules and data models
│   ├── auth.py            - Asymmetric JWT/OIDC public-key token verifier
│   ├── models.py          - User/Document schemas and sample classified store
│   ├── policy_engine.py   - Dual-gate orchestrator (LLM Guard, OPA, Watermarking)
│   ├── opa_client.py      - Fail-closed REST client for Open Policy Agent (OPA)
│   ├── tracker.py         - Valkey Sorted Set (ZSET) tracker over mTLS + ACL
│   ├── vector_store.py    - Qdrant client over TLS + FastEmbed local embeddings
│   ├── entity_tagger.py   - Offline Presidio + spaCy NER tagger for Mosaic rules
│   └── output_guard.py    - Post-retrieval DLP regex scanner and redactor
├── scripts/               - Operational helpers and standalone demo entrypoints
├── tests/                 - Policy, authentication, DLP, and watermark tests
├── config/                - Valkey and Qdrant service configurations
├── docs/                  - Architecture and deployment documentation
├── policy.rego            - Declarative Rego policies (ABAC, Rate Limit, Mosaic)
├── policy_test.rego       - Direct unit tests for the Rego authorization rules
├── .github/workflows/
│   └── ci.yml             - GitHub Actions CI pipeline
├── requirements.txt       - Python dependencies
├── Dockerfile             - Air-gapped container build (pre-caches ONNX & spaCy)
└── docker-compose.yml     - Orchestrates FastAPI, Valkey, OPA, and Qdrant


4. QUICKSTART & DEPLOYMENT GUIDE
--------------------------------------------------------------------------------
Step 1: Generate Internal CA & Service TLS Certificates
  mkdir -p certs && cd certs
  openssl req -x509 -newkey rsa:4096 -days 365 -nodes -keyout ca.key -out ca.crt -subj "/CN=DefenseCA"

  # Valkey server & client mTLS certs
  openssl req -newkey rsa:4096 -nodes -keyout valkey.key -out valkey.csr -subj "/CN=valkey"
  openssl x509 -req -in valkey.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out valkey.crt -days 365
  openssl req -newkey rsa:4096 -nodes -keyout client.key -out client.csr -subj "/CN=policy-proxy"
  openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365

  # Qdrant server TLS cert
  openssl req -newkey rsa:4096 -nodes -keyout qdrant.key -out qdrant.csr -subj "/CN=qdrant"
  openssl x509 -req -in qdrant.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out qdrant.crt -days 365
  cd ..

Step 2: Configure Secrets
  - Replace REPLACE_WITH_STRONG_VALKEY_PASSWORD in config/valkey.conf and docker-compose.yml.
  - Replace REPLACE_WITH_STRONG_QDRANT_API_KEY in config/qdrant_config.yaml and docker-compose.yml.

Step 3: Generate IdP Signing Keys & Test JWT
  python scripts/generate_test_jwt.py
  # Saves certs/idp_public.pem and prints: export TEST_JWT='<signed_token>'

Step 4: Build & Start the Air-Gapped Stack
  # Note: The initial docker build downloads and caches ONNX + spaCy models inside
  # the image so runtime execution requires zero internet connectivity.
  docker compose up -d --build

Step 5: Auto-Tag & Ingest Classified Documents into Qdrant
  docker exec -it defense-policy-proxy python scripts/ingest_docs.py

Step 6: Query the Protected Retrieval API
  curl -X POST http://localhost:8000/v1/retrieve \
    -H "Authorization: Bearer $TEST_JWT" \
    -H "Content-Type: application/json" \
    -d '{"prompt": "What are the perimeter specifications and guard shifts at Base Alpha?"}'


5. TESTING
--------------------------------------------------------------------------------
Run the Python unit tests:
  python -m pytest -v tests

Run the Rego policy tests directly with OPA:
  opa test .

The policy_test.rego suite verifies authorized access, insufficient clearance,
missing compartment access, volumetric rate limits, and Mosaic aggregation blocks.
Tests are also executed automatically by GitHub Actions using .github/workflows/ci.yml
for every push and pull request. The CI pipeline uses Python 3.11, runs the Python
and Rego test suites, checks Python syntax, and validates the Docker Compose config.


6. FORENSIC LEAK TRACING
--------------------------------------------------------------------------------
Every approved document returned by /v1/retrieve contains invisible zero-width
Unicode characters (\u200b and \u200c) encoding the authenticated user's ID.

If sensitive text is copy-pasted and leaked externally:
  1. Paste the leaked snippet into src/watermark_decoder.py (or import decode_watermark).
  2. Run: python src/watermark_decoder.py
  3. The script decodes the binary watermark and outputs the originating user_id.


7. OPERATIONAL & SECURITY NOTES
--------------------------------------------------------------------------------
- Fail-Closed Enforcement: If OPA, Valkey, or Qdrant becomes unreachable or fails
  TLS verification, all document retrievals are denied automatically.
- Modifying Policies: Edit policy.rego to adjust clearance rules, hourly volume
  thresholds, or Mosaic forbidden_combinations without rebuilding Python code.
- Offline Air-Gap Operation: HF_HUB_OFFLINE=1 and TRANSFORMERS_OFFLINE=1 are set
  in the Dockerfile so no outbound network requests occur at runtime.
================================================================================
