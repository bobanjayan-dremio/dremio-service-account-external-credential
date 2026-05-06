# dremio_connect.py
import time, json, requests
import jwt  # pip install PyJWT
from cryptography.hazmat.primitives.serialization import load_pem_private_key

DREMIO_HOST = "a76a499f9f81844d69ab8ed9990eec9f-483161425.us-east-1.elb.amazonaws.com"
DREMIO_BASE = f"https://{DREMIO_HOST}"

# --- Must match what you configured in the Dremio external credential ---
ISSUER    = "https://my-test-issuer.local"
AUDIENCE  = "https://dremio.example.com"
SUBJECT   = "dremio-service-account"   # must match External ID in Dremio UI
KID       = "dremio-test-key-1"        # must match kid in your jwks.json


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
        "exp": now + 900,  # 15 minutes
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
            "subject_token": external_jwt,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "scope": "dremio.all",
            "audience": "//oauth.dremio.app/clients/c277ee61-4230-4a6a-8f4f-d65831b283cb/credentials/fe8436bc-1bbc-4408-aaf3-326934696dd7"
        },
        verify=False  # swap for your CA cert path if using self-signed TLS
    )
    resp.raise_for_status()
    token_data = resp.json()
    print(f" Dremio token obtained, expires in {token_data['expires_in']}s")
    return token_data["access_token"]


def run_query(dremio_token, sql):
    """Submit a SQL query and poll for results."""
    headers = {"Authorization": f"Bearer {dremio_token}", "Content-Type": "application/json"}

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
        state = status_resp.json()["jobState"]
        if state == "COMPLETED":
            break
        if state in ("FAILED", "CANCELLED"):
            raise RuntimeError(f"Job {job_id} ended with state: {state}")
        time.sleep(1)

    # Fetch results
    results = requests.get(
        f"{DREMIO_BASE}/api/v3/job/{job_id}/results?offset=0&limit=10",
        headers=headers, verify=False
    )
    return results.json()


if __name__ == "__main__":
    private_key = load_private_key()
    ext_jwt     = get_signed_jwt(private_key)
    dremio_token = exchange_jwt_for_dremio_token(ext_jwt)

    result = run_query(dremio_token, """SELECT * FROM Samples."samples.dremio.com".citibikes limit 5""")
    print(json.dumps(result, indent=2))
