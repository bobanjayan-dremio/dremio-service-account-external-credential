# Dremio Service User Authentication via External Credential (Self-Signed JWT)

This guide documents how to configure a Dremio service user to authenticate using a self-signed JWT, eliminating the need for rotating OAuth secrets. The external credential approach uses short-lived tokens (15 min) and requires zero maintenance — no rotation, no expiry.

Choose the option that matches your environment:

- **[Option A](#option-a-host-jwks-on-s3--github)** — Cloud / AWS EKS / public URL available
- **[Option B](#option-b-host-jwks-inside-the-cluster-via-nginx)** — On-prem / air-gapped / no public URL

---

## How It Works

```
[Your Script / Automation]
    │
    │  1. Load private_key.pem → sign JWT (15 min TTL)
    ▼
[/oauth/token endpoint on Dremio]
    │
    │  2. Dremio fetches JWKS from hosting location → verifies JWT signature
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
- `kubectl` access to the cluster running Dremio
- Dremio admin access to configure service users

### Install Python dependencies

```bash
pip install cryptography PyJWT requests
```

> ⚠️ Do **not** install the `jwt` package — it conflicts with `PyJWT`. If already installed, remove it first:
> ```bash
> pip uninstall jwt PyJWT -y && pip install PyJWT
> ```

---

## Generate RSA Key Pair and JWKS

Run `setup_keys.py` **once** regardless of which hosting option you choose.

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

# Build JWKS (public key only) — safe to host publicly
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

print("private_key.pem — keep secret, never share")
print("jwks.json       — upload to your chosen hosting location")
```

```bash
python setup_keys.py
```

> **Security note:** `jwks.json` contains only the RSA *public* key. It is safe to expose publicly — this is the same pattern used by Okta, Entra ID, and Google. Keep `private_key.pem` secret at all times.

---

## Create a Service User in Dremio

1. Go to **Settings → User Management → Service Users**
2. Click **Add Service User**
3. Provide a **Username** (e.g. `automation-svc`) and optional description
4. Click **Save**
5. Go to **Granted Roles** and assign at least the `PUBLIC` role, plus any roles needed for the data sources the automation will query

---

---

# Option A: Host JWKS on S3 / GitHub

Use this option when Dremio runs on AWS EKS or any environment with access to a public URL.

---

## Step A-1: Upload jwks.json to S3 or GitHub

### S3 (public bucket)

```bash
aws s3 cp jwks.json s3://<your-bucket>/dremio-jwks/jwks.json --acl public-read

# JWKS URL:
# https://<your-bucket>.s3.amazonaws.com/dremio-jwks/jwks.json
```

### GitHub

Commit `jwks.json` to your repository and use the raw URL:

```
https://raw.githubusercontent.com/<org>/<repo>/main/jwks.json
```

> To get the raw URL: open the file in GitHub → click the **Raw** button → copy the URL from your browser.

---

## Step A-2: Verify JWKS is Reachable from Dremio Pods

```bash
# Find the coordinator pod
kubectl get pods -n <dremio-namespace> | grep coordinator

# Test connectivity from inside the pod
kubectl exec -it <coordinator-pod-name> -n <dremio-namespace> -- \
  curl -v https://<your-bucket>.s3.amazonaws.com/dremio-jwks/jwks.json
```

Expected: HTTP 200 with the JWKS JSON body returned.

---

## Step A-3: Configure External Credential in Dremio UI

Navigate to: **Settings → User Management → Service Users → [your service user] → Credentials → Add → Configure an external credential**

| Field | Value | Notes |
|-------|-------|-------|
| **Label** | `test-self-signed` | Display name only — choose anything |
| **Audience** | `https://dremio.example.com` | Must match `aud` claim in the JWT exactly |
| **User claim** | `sub` | JWT field that identifies the service account |
| **External ID** | `dremio-service-account` | Must match the `sub` value in the JWT exactly |
| **Issuer URL** | `https://my-test-issuer.local` | Must match `iss` claim in the JWT exactly |
| **JWKS URL** | `https://<your-bucket>.s3.amazonaws.com/dremio-jwks/jwks.json` | Where Dremio fetches the public key to verify signatures |

Click **Configure**.

### Field Matching Diagram

```
Script constant              JWT claim        Dremio UI field
──────────────────────────────────────────────────────────────
ISSUER   = "https://my-test-issuer.local"  →  Issuer URL
AUDIENCE = "https://dremio.example.com"   →  Audience
SUBJECT  = "dremio-service-account"       →  External ID
                   sub claim              →  User claim = "sub"

KID = "dremio-test-key-1"  → matches "kid" in jwks.json
                              (not configured in UI)
```

### Copy the Exchange Request URI

After clicking Configure, the credential card shows an **Exchange Request** field:

```
//oauth.dremio.app/clients/<client-id>/credentials/<credential-id>
```

Click the copy icon next to it — this value is required as the `audience` parameter in the token exchange call.

---

## Step A-4: Run the Python Script

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
    job_resp = requests.post(
        f"{DREMIO_BASE}/api/v3/sql",
        headers=headers,
        json={"sql": sql},
        verify=False
    )
    job_resp.raise_for_status()
    job_id = job_resp.json()["id"]
    print(f"  Job submitted: {job_id}")

    while True:
        job_data = requests.get(
            f"{DREMIO_BASE}/api/v3/job/{job_id}",
            headers=headers, verify=False
        ).json()
        state = job_data["jobState"]
        if state == "COMPLETED":
            break
        if state in ("FAILED", "CANCELLED"):
            print(f"  Error: {job_data.get('errorMessage')}")
            raise RuntimeError(f"Job {job_id} ended with state: {state}")
        time.sleep(1)

    return requests.get(
        f"{DREMIO_BASE}/api/v3/job/{job_id}/results?offset=0&limit=10",
        headers=headers, verify=False
    ).json()


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

---

# Option B: Host JWKS Inside the Cluster via nginx

Use this option when Dremio runs on-prem or in an environment with no public URL. The JWKS is served from inside the cluster over plain HTTP, avoiding any SSL trust issues.

---

## Step B-1: Extract JWKS from Kubernetes

```bash
# Extract the cluster's public signing keys
kubectl get --raw /openid/v1/jwks > jwks.json

# Verify the output
cat jwks.json
```

Expected:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "kid": "f295c3b0b16f296d87ac9698ff177b126d4967d8",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

> For the self-signed JWT approach (no Kubernetes token), use the `jwks.json` generated by `setup_keys.py` instead.

---

## Step B-2: Create ConfigMap

```bash
kubectl create configmap jwks-config \
  --from-file=jwks.json=jwks.json \
  -n default

# Verify
kubectl describe configmap jwks-config -n default
```

---

## Step B-3: Deploy nginx to Serve the JWKS

Save the following as `jwks-server.yaml` and apply it:

```yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jwks-server
  namespace: default
  labels:
    app: jwks-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: jwks-server
  template:
    metadata:
      labels:
        app: jwks-server
    spec:
      containers:
        - name: nginx
          image: nginx:alpine
          ports:
            - containerPort: 80
          volumeMounts:
            - name: jwks-volume
              mountPath: /usr/share/nginx/html
          livenessProbe:
            httpGet:
              path: /jwks.json
              port: 80
            initialDelaySeconds: 5
            periodSeconds: 10
      volumes:
        - name: jwks-volume
          configMap:
            name: jwks-config
---
apiVersion: v1
kind: Service
metadata:
  name: jwks-server
  namespace: default
spec:
  selector:
    app: jwks-server
  ports:
    - protocol: TCP
      port: 80
      targetPort: 80
  type: ClusterIP
```

```bash
kubectl apply -f jwks-server.yaml

# Verify pod and service are running
kubectl get pods -n default | grep jwks
kubectl get svc  -n default | grep jwks
```

---

## Step B-4: Verify JWKS is Reachable from Dremio Pods

```bash
kubectl exec -it <dremio-coordinator-pod> -n <dremio-namespace> -- \
  curl -v http://jwks-server.default.svc.cluster.local/jwks.json
```

Expected: HTTP 200 with the JWKS JSON body returned.

---

## Step B-5: Configure External Credential in Dremio UI

Navigate to: **Settings → User Management → Service Users → [your service user] → Credentials → Add → Configure an external credential**

| Field | Value | Notes |
|-------|-------|-------|
| **Label** | `k8s-svc-acct-test` | Display name only — choose anything |
| **Audience** | `https://<dremio-host>/oauth/token` | Must match `aud` claim in the JWT exactly |
| **User claim** | `sub` | JWT field that identifies the service account |
| **External ID** | `system:serviceaccount:default:dremio-access-test` | Must match the `sub` value in the JWT exactly |
| **Issuer URL** | `https://kubernetes.default.svc` | Must match `iss` claim in the JWT exactly |
| **JWKS URL** | `http://jwks-server.default.svc.cluster.local/jwks.json` | Internal nginx service — no SSL, no public URL needed |

Click **Configure**.

### Copy the Exchange Request URI

After clicking Configure, the credential card shows an **Exchange Request** field:

```
//oauth.dremio.app/clients/<client-id>/credentials/<credential-id>
```

Click the copy icon next to it — this value is required as the `audience` parameter in the token exchange call.

---

## Step B-6: Restart Dremio Coordinator

After setting the JWKS URL, restart the coordinator so the ETP registry is rebuilt with the new URL:

```bash
kubectl rollout restart statefulset dremio-master -n <dremio-namespace>

# Confirm ETP registers successfully in startup logs
kubectl logs -f <dremio-coordinator-pod> -n <dremio-namespace> \
  | grep -i "ETP\|external token"
```

---

## Step B-7: Test Token Exchange

```bash
DREMIO_HOST="<your-dremio-hostname>"
EXCHANGE_REQUEST="//oauth.dremio.app/clients/<client-id>/credentials/<credential-id>"

# Generate a Kubernetes service account token
AUTH_TOKEN=$(kubectl create token dremio-access-test \
  --audience="https://${DREMIO_HOST}/oauth/token" \
  --duration=1h \
  -n default)

# Exchange for a Dremio access token
curl -s -X POST "https://${DREMIO_HOST}/oauth/token" \
  -k \
  --data-urlencode "scope=dremio.all" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
  --data-urlencode "subject_token=$AUTH_TOKEN" \
  --data-urlencode "audience=$EXCHANGE_REQUEST" | python3 -m json.tool
```

Expected response:
```json
{
  "access_token": "eyJ...",
  "expires_in": 899,
  "token_type": "Bearer",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "scope": "dremio.all"
}
```

### Updating jwks.json in Future

If the cluster signing keys are ever rotated:

```bash
kubectl get --raw /openid/v1/jwks > jwks.json

kubectl create configmap jwks-config \
  --from-file=jwks.json=jwks.json \
  -n default \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl rollout restart deployment jwks-server -n default
```

---

---

# Maintenance

| Component | Action Required | Frequency |
|-----------|----------------|-----------|
| `private_key.pem` | None | Never expires |
| `jwks.json` on S3/GitHub/nginx | None | Never expires |
| Dremio external credential | None | No TTL |
| JWT generated by script | Auto-generated fresh at runtime | Every run |
| Dremio access token | Auto-obtained fresh at runtime | Every run |

**This setup requires zero maintenance.** Run the script in 6 months or 2 years — it will work without any changes.

---

# Troubleshooting

| Error | Likely Cause | Fix |
|-------|-------------|-----|
| `401 Invalid token` | `audience` param missing in token exchange | Add `EXCHANGE_REQUEST` to the POST data |
| `401 Invalid token` | Claim mismatch (`iss`, `aud`, or `sub`) | Verify script constants match Dremio UI fields exactly |
| `401 Invalid token` | JWKS unreachable from pod | Run `kubectl exec` curl test from coordinator pod |
| `403` on query | Service user missing role/privilege | Go to Granted Roles and assign appropriate permissions |
| `0 ETPs were found` | JWKS URL empty or unreachable at coordinator startup | Set JWKS URL explicitly in Dremio UI; restart coordinator; check startup logs |
| `0 ETPs were found` on on-prem | `kubernetes.default.svc` cert not trusted by Dremio JVM | Use Option B — nginx in-cluster serves over plain HTTP, no SSL trust issue |
| `INVALID_ARGUMENT: Failed to fetch JWKS` at save time | JWKS URL unreachable from Dremio pod at UI save time | Verify nginx pod is running and reachable before configuring credential |
| `AttributeError: module 'jwt' has no attribute 'encode'` | Wrong `jwt` package installed | `pip uninstall jwt PyJWT -y && pip install PyJWT` |

---

# Security Notes

- `private_key.pem` is the only secret. Store it in AWS Secrets Manager or Vault for production use.
- `jwks.json` is public by design — it contains only the RSA public key.
- JWTs are short-lived (15 min). Even if intercepted, they expire quickly.
- The Dremio access token is also short-lived (~15 min).
- For production on EKS, consider replacing `private_key.pem` with IRSA/EKS Pod Identity — eliminates any stored secret entirely.
