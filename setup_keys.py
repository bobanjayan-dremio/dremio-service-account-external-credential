# setup_keys.py  — run ONCE to generate keys
import json, base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Save private key (keep this secret, never upload)
with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Build JWKS (public key in JWK format) — this is what you upload to S3
pub = private_key.public_key().public_numbers()

def _b64(n):
    return base64.urlsafe_b64encode(
        n.to_bytes((n.bit_length() + 7) // 8, "big")
    ).rstrip(b"=").decode()

jwks = {
    "keys": [{
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "dremio-test-key-1",
        "n": _b64(pub.n),
        "e": _b64(pub.e),
    }]
}

with open("jwks.json", "w") as f:
    json.dump(jwks, f, indent=2)

print(" private_key.pem  — keep secret")
print(" jwks.json        — upload this to S3")
