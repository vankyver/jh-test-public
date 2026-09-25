
import concurrent.futures
import re
import socket
import time

import requests
import streamlit as st

SECRET_RE = re.compile(r"(token|session|secret|password|auth|jwt)", re.I)

NETWORK_TARGETS = [
    "1.1.1.1"
]


def probe_host(host, timeout=4):
    row = {"host": host, "dns": "", "tcp/443": "", "tcp/80": "", "http": ""}
    try:
        row["dns"] = socket.gethostbyname(host)
    except Exception as e:
        row["dns"] = f"FAIL ({e.__class__.__name__})"
        row["tcp/443"] = row["tcp/80"] = row["http"] = "skipped (no DNS)"
        return row

    for key, port in (("tcp/443", 443), ("tcp/80", 80)):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                row[key] = "open"
        except Exception as e:
            row[key] = f"closed/filtered ({e.__class__.__name__})"

    for scheme in ("https", "http"):
        try:
            t0 = time.monotonic()
            r = requests.get(f"{scheme}://{host}/", timeout=timeout,
                             allow_redirects=False, verify=True)
            dt = time.monotonic() - t0
            row["http"] = f"{scheme.upper()} {r.status_code} ({dt:.2f}s)"
            break
        except requests.exceptions.SSLError as e:
            row["http"] = f"{scheme.upper()} TLS error: {e.__class__.__name__}"
        except Exception as e:
            row["http"] = f"{scheme.upper()} error: {e.__class__.__name__}"
    return row


def mask(name: str, value: str) -> str:
    if not SECRET_RE.search(name) or len(value) <= 12:
        return value
    return f"{value[:6]}...<{len(value)} chars redacted>...{value[-4:]}"


st.title("Cookie / header echo -- security review")
st.caption("Shows exactly what THIS app's backend received, to check cookie scoping "
           "across tenants/apps on the platform.")

cookies = dict(st.context.cookies)
headers = dict(st.context.headers)

st.subheader(f"Cookies received ({len(cookies)})")
if cookies:
    st.table({"cookie": list(cookies.keys()),
              "value": [mask(k, v) for k, v in cookies.items()]})
    flagged = [k for k in cookies if k.startswith("jupyterhub-user-") or k == "jhub_apps_access_token"]
    if flagged:
        st.error(f"This unrelated app just received your hub auth cookie(s) server-side: {flagged}")
else:
    st.write("No cookies received.")

st.subheader(f"All headers received ({len(headers)})")
st.table({"header": list(headers.keys()),
          "value": [mask(k, v) for k, v in headers.items()]})

st.caption(f"client IP as seen by this app: {st.context.ip_address}")

st.subheader("Network reachability from THIS app's pod")
if st.button("Run reachability checks"):
    with st.spinner("probing..."):
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(NETWORK_TARGETS)) as ex:
            rows = list(ex.map(probe_host, NETWORK_TARGETS))
    st.table(rows)
else:
    st.caption("Click the button to test egress from this pod to: "
               + ", ".join(NETWORK_TARGETS))
