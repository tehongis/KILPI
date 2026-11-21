import datetime
import os
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

os.makedirs("certs", exist_ok=True)

# 1. Generate RSA 2048-bit keypair simulating your Identity Provider (IdP)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

with open("idp_private.pem", "wb") as f:
    f.write(private_pem)
with open("certs/idp_public.pem", "wb") as f:
    f.write(public_pem)

# 2. Mint a signed JWT for Contractor CTR-8821
now = datetime.datetime.now(datetime.timezone.utc)
claims = {
    "sub": "CTR-8821",
    "role": "contractor",
    "clearance": 2,
    "compartments": ["FACILITY_ALPHA"],
    "iss": "https://defense.internal",
    "aud": "defense-llm-proxy",
    "iat": now,
    "exp": now + datetime.timedelta(minutes=30),
}

token = jwt.encode(claims, private_pem, algorithm="RS256")
print("Saved public key to certs/idp_public.pem\n")
print(f"export TEST_JWT='{token}'")
