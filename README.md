# Dremio Service User Authentication via External Credential (Self-Signed JWT)

This guide documents how to configure a Dremio service user to authenticate using a self-signed JWT, eliminating the need for rotating OAuth secrets. The external credential approach uses short-lived tokens (15 min) and requires zero maintenance — no rotation, no expiry.

---

## Architecture Overview

```
[Your Script / Automation]
    │
    │  1. Load private_key.pem → sign JWT (15 min TTL)
    ▼
[/oauth/token endpoint on Dremio]
    │
    │  2. Dremio fetches JWKS from S3 → verifies JWT signature
    │  3. Returns short-lived Dremio access token (~15 min)
    ▼
[Dremio REST API]
    │
    │  4. Execute queries using Bearer token
    ▼
[Results]
```

---

## Prerequisites

- Python 3.8+
- AWS S3 bucket (public-read or accessible from Dremio pods)
- `kubectl` access to the EKS cluster running Dremio
- Dremio admin access to configure service users

### Install Python dependencies

```bash
pip install cryptography PyJWT requests
```

>  Do **not** install the `jwt` package — it conflicts with `PyJWT`. If already installed, remove it first:
> ```bash
> pip uninstall jwt PyJWT -y && pip install PyJWT
> ```

---

## Step 1: Generate RSA Key Pair and JWKS

Run `setup_keys.py` **once** to generate your RSA key pair and the JWKS file.

```python
# setup_keys.py
import json, base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Save private key — keep this secret, never upload
with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Build JWKS (public key only) — this is safe to upload to S3
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

print(" private_key.pem — keep secret, never share")
print(" jwks.json       — upload to S3")
```

```bash
python setup_keys.py
```

### Upload JWKS to S3

```bash
# Public bucket (simplest for testing)
aws s3 cp jwks.json s3://<your-bucket>/dremio-jwks/jwks.json --acl public-read

# Your JWKS URL will be:
# https://<your-bucket>.s3.amazonaws.com/dremio-jwks/jwks.json
```

> **Security note:** `jwks.json` contains only the RSA *public* key. It is safe to expose publicly — this is the same pattern used by Okta, Entra ID, and Google. Keep `private_key.pem` secret.

---

## Step 2: Verify JWKS is Reachable from Dremio Pods

Since Dremio runs on EKS, the coordinator pod must be able to fetch the JWKS URL at token exchange time.

```bash
# Test connectivity from inside the pod
kubectl exec -it dremio-master-0 -n <dremio-namespace> -- \
  curl -v https://<your-bucket>.s3.amazonaws.com/dremio-jwks/jwks.json
```

Expected: HTTP 200 with the JWKS JSON body returned.

---

## Step 3: Create a Service User in Dremio

1. Go to **Settings → User Management → Service Users**
2. Click **Add Service User**
3. Provide a **Username** (e.g. `automation-svc`) and optional description
4. Click **Save**
5. Go to **Granted Roles** and assign at least the `PUBLIC` role, plus any roles needed for the data sources the automation will query

---

## Step 4: Configure External Credential in Dremio UI

Navigate to: **Settings → User Management → Service Users → [your service user] → Credentials → Add → Configure an external credential**

Fill in the fields as follows:

| Field | Value | Notes |
|-------|-------|-------|
| **Label** | `test-self-signed` | Display name only — choose anything |
| **Audience** | `https://dremio.example.com` | Must match `aud` claim in the JWT exactly |
| **User claim** | `sub` | JWT field that identifies the service account |
| **External ID** | `dremio-service-account` | Must match the `sub` value in the JWT exactly |
| **Issuer URL** | `https://my-test-issuer.local` | Must match `iss` claim in the JWT exactly |
| **JWKS URL** | `https://<your-bucket>.s3.amazonaws.com/dremio-jwks/jwks.json` | Where Dremio fetches the public key to verify signatures |

Click **Configure**.

<img width="630" height="536" alt="1_DremioUI" src="https://github.com/user-attachments/assets/52d009cf-911c-40fa-9f18-e73fa3646276" />
<img width="867" height="425" alt="2_DremioUI" src="https://github.com/user-attachments/assets/7a9871b7-ee7e-48f4-b39e-ec110f564d68" />


### Field Matching Diagram

```
dremio_connect.py constant     JWT claim     Dremio UI field
───────────────────────────────────────────────────────────
ISSUER   = "https://my-test-issuer.local"  →  Issuer URL
AUDIENCE = "https://dremio.example.com"   →  Audience
SUBJECT  = "dremio-service-account"       →  External ID
                    ↑
               sub claim                  →  User claim = "sub"

KID      = "dremio-test-key-1"  ─→  matches "kid" in jwks.json
                                    (not configured in UI)
```

### After saving, note the Exchange Request URI

After clicking Configure, the credential card shows an **Exchange Request** field:

```
//oauth.dremio.app/clients/<client-id>/credentials/<credential-id>
```

Copy this full value — it is required as the `audience` parameter in the token exchange call.

---

## Step 5: Run the Script

```python
# dremio_connect.py
import time, json, requests
import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

DREMIO_HOST      = "<your-dremio-hostname>"
DREMIO_BASE      = f"https://{DREMIO_HOST}"
ISSUER           = "https://my-test-issuer.local"
AUDIENCE         = "https://dremio.example.com"
SUBJECT          = "dremio-service-account"
KID              = "dremio-test-key-1"
EXCHANGE_REQUEST = "//oauth.dremio.app/clients/<client-id>/credentials/<credential-id>"


def load_private_key(path="private_key.pem"):
    with open(path, "rb") as f:
        return load_pem_private_key(f.read(), password=None)


def get_signed_jwt(private_key):
    """Create and sign a short-lived JWT (15 minutes)."""
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": SUBJECT,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 900,
    }
    return jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": KID}
    )


def exchange_jwt_for_dremio_token(external_jwt):
    """Exchange the external JWT for a Dremio OAuth access token."""
    resp = requests.post(
        f"{DREMIO_BASE}/oauth/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "subject_token":      external_jwt,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
            "scope":              "dremio.all",
            "audience":           EXCHANGE_REQUEST,
        },
        verify=False
    )
    resp.raise_for_status()
    token_data = resp.json()
    print(f"Dremio token obtained, expires in {token_data['expires_in']}s")
    return token_data["access_token"]


def run_query(dremio_token, sql):
    """Submit a SQL query and poll for results."""
    headers = {
        "Authorization": f"Bearer {dremio_token}",
        "Content-Type":  "application/json"
    }

    # Submit job
    job_resp = requests.post(
        f"{DREMIO_BASE}/api/v3/sql",
        headers=headers,
        json={"sql": sql},
        verify=False
    )
    job_resp.raise_for_status()
    job_id = job_resp.json()["id"]
    print(f"  Job submitted: {job_id}")

    # Poll until complete
    while True:
        status_resp = requests.get(
            f"{DREMIO_BASE}/api/v3/job/{job_id}",
            headers=headers, verify=False
        )
        job_data = status_resp.json()
        state = job_data["jobState"]
        if state == "COMPLETED":
            break
        if state in ("FAILED", "CANCELLED"):
            error_msg = job_data.get("errorMessage", "no errorMessage field")
            print(f"  Error: {error_msg}")
            raise RuntimeError(f"Job {job_id} ended with state: {state}")
        time.sleep(1)

    # Fetch results
    results = requests.get(
        f"{DREMIO_BASE}/api/v3/job/{job_id}/results?offset=0&limit=10",
        headers=headers, verify=False
    )
    return results.json()


if __name__ == "__main__":
    private_key  = load_private_key()
    ext_jwt      = get_signed_jwt(private_key)
    dremio_token = exchange_jwt_for_dremio_token(ext_jwt)
    result       = run_query(dremio_token, "SELECT 1 AS test_col")
    print(json.dumps(result, indent=2))
```

```bash
python dremio_connect.py
```

Expected output:
```
  Dremio token obtained, expires in 899s
  Job submitted: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
{
  "rowCount": 1,
  "schema": [{"name": "test_col", "type": {"name": "INTEGER"}}],
  "rows": [{"test_col": 1}]
}
```

---

## Maintenance

| Component | Action required | Frequency |
|-----------|----------------|-----------|
| `private_key.pem` | None | Never expires |
| `jwks.json` on S3 | None | Never expires |
| Dremio external credential | None | No TTL |
| JWT generated by script | Auto-generated fresh at runtime | Every run |
| Dremio access token | Auto-obtained fresh at runtime | Every run |

**This setup requires zero maintenance.** Run the script in 6 months or 2 years — it will work without any changes.

---

## Troubleshooting

| Error | Likely cause | Fix |
|-------|-------------|-----|
| `401 Invalid token` | `audience` param missing in token exchange | Add `EXCHANGE_REQUEST` to the POST data |
| `401 Invalid token` | Claim mismatch (`iss`, `aud`, or `sub`) | Verify constants match Dremio UI fields exactly |
| `401 Invalid token` | JWKS unreachable from pod | Run `kubectl exec` curl test from coordinator pod |
| `403` on query | Service user missing role/privilege | Go to Granted Roles and assign appropriate permissions |
| `AttributeError: module 'jwt' has no attribute 'encode'` | Wrong `jwt` package installed | `pip uninstall jwt PyJWT -y && pip install PyJWT` |

---

## Security Notes

- `private_key.pem` is the only secret. Store it in AWS Secrets Manager or Vault for production use.
- `jwks.json` is public by design — it contains only the RSA public key.
- JWTs are short-lived (15 min). Even if intercepted, they expire quickly.
- The Dremio access token is also short-lived (~15 min).
- For production on EKS, consider replacing `private_key.pem` with IRSA/EKS Pod Identity — eliminates the need for any stored secret entirely.
