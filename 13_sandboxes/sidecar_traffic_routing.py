# ---
# cmd: ["python", "13_sandboxes/sidecar_traffic_routing.py"]
# pytest: false
# ---

# # Filter Sandbox HTTPS traffic with a proxy Sidecar

# A proxy Sidecar can inspect and restrict HTTPS requests made by otherwise
# proxy-unaware programs in a Sandbox. This example permits only `GET` requests
# to the `modal-labs/modal-client` repository on `github.com`, while forwarding
# requests to all other domains without applying the filter.

# We use [mitmproxy](https://mitmproxy.org/) to terminate TLS, parse HTTP, connect to
# GitHub, and generate certificates. HTTPS traffic is encrypted, so to determine the
# request path the sidecar must be in the middle of the connection, and perform the
# encryption/decryption against both the original client and server instead.

import tempfile
from pathlib import Path

import modal

app = modal.App.lookup("example-sidecar-traffic-routing", create_if_missing=True)

SIDECAR_NAME = "proxy"
MITMPROXY_CONFIG_DIR = "/tmp/mitmproxy"
MITMPROXY_CA_CERT = f"{MITMPROXY_CONFIG_DIR}/mitmproxy-ca-cert.pem"
SANDBOX_CA_CERT = "/tmp/mitmproxy-ca-cert.pem"

# ## Define the request policy

# To configure mitmproxy dynamically we use an addon script. The `tls_clienthello`
# hook is used to parse the hostname and port from the `ClientHello` [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication).
# After decrypting and parsing a request, the `request` hook applies the GitHub-specific
# request path policy.

MITMPROXY_ADDON = """\
from mitmproxy import http, tls

FILTERED_HOST = "github.com"
ALLOWED_REPOSITORY = "/modal-labs/modal-client"


def tls_clienthello(data: tls.ClientHelloData) -> None:
    hostname = data.client_hello.sni
    if hostname:
        data.context.server.address = (hostname, 443)
        data.context.server.sni = hostname


def request(flow: http.HTTPFlow) -> None:
    request = flow.request
    hostname = (flow.client_conn.sni or "").lower()
    if hostname != FILTERED_HOST:
        return

    raw_path = request.path.split("?", 1)[0]
    segments = raw_path.split("/")
    repository_segments = ["", *ALLOWED_REPOSITORY.strip("/").split("/")]
    # Reject alternate path spellings that GitHub could normalize after this check.
    allowed_path = (
        segments[: len(repository_segments)] == repository_segments
        and all(segment not in {".", ".."} for segment in segments)
        and "%" not in raw_path
        and "\\\\" not in raw_path
    )
    if (
        request.method == "GET"
        and request.pretty_host == FILTERED_HOST
        and allowed_path
    ):
        return

    flow.response = http.Response.make(
        403,
        b"This Sandbox may only GET github.com/modal-labs/modal-client.\\n",
        {"Content-Type": "text/plain"},
    )
"""

# We install mitmproxy and copy the policy addon into its Image.

with tempfile.TemporaryDirectory() as tmp_dir:
    addon_path = Path(tmp_dir) / "github_filter.py"
    addon_path.write_text(MITMPROXY_ADDON)
    with modal.enable_output():
        sidecar_image = (
            modal.Image.debian_slim(python_version="3.12")
            .pip_install("mitmproxy==12.2.3")
            .add_local_file(addon_path, "/github_filter.py", copy=True)
            .build(app)
        )

sandbox_image = modal.Image.debian_slim().apt_install("curl")

# ## Start the Sandbox and proxy Sidecar

# The experimental option names the Sidecar that receives all outbound TCP traffic on
# port 443. HTTPS fails closed until that Sidecar is running.

with modal.enable_output():
    sandbox = modal.Sandbox.create(
        "sleep",
        "600",
        app=app,
        image=sandbox_image,
        timeout=5 * 60,
        experimental_options={"proxy_traffic_via_sidecar": SIDECAR_NAME},
    )
print(f"Sandbox ID: {sandbox.object_id}")

sidecar = sandbox._experimental_sidecars.create(
    "mitmdump",
    "--mode",
    "reverse:https://invalid.invalid@443",
    "--set",
    f"confdir={MITMPROXY_CONFIG_DIR}",
    "--set",
    "connection_strategy=lazy",
    "--set",
    "keep_host_header=true",
    "--scripts",
    "/github_filter.py",
    name=SIDECAR_NAME,
    image=sidecar_image,
)
print(f"Sidecar ID: {sidecar.object_id}")

# ## Trust the proxy's certificate authority

# Mitmproxy creates a unique certificate authority on first startup. Copy only its
# public certificate into the main Sandbox and pass it to curl. The CA private key
# remains isolated in the Sidecar.

read_ca = sidecar.exec(
    "bash",
    "-c",
    f"until test -s {MITMPROXY_CA_CERT} "
    "&& (echo > /dev/tcp/127.0.0.1/443) 2>/dev/null; "
    f"do sleep 0.1; done; cat {MITMPROXY_CA_CERT}",
    timeout=1 * 60,
)
ca_certificate = read_ca.stdout.read()
if read_ca.wait() != 0:
    raise RuntimeError(read_ca.stderr.read())

write_ca = sandbox.exec("tee", SANDBOX_CA_CERT)
write_ca.stdin.write(ca_certificate)
write_ca.stdin.write_eof()
write_ca.stdin.drain()
if write_ca.wait() != 0:
    raise RuntimeError(write_ca.stderr.read())

# ## Exercise the policy

# These requests use an ordinary GitHub URL with no explicit HTTP proxy settings. The
# first request reaches GitHub through the Sidecar. The next three are answered by the
# addon and never reach GitHub. The final request demonstrates that another domain is
# forwarded normally.


def request_status(method: str, url: str) -> str:
    process = sandbox.exec(
        "curl",
        "--cacert",
        SANDBOX_CA_CERT,
        "--request",
        method,
        "--path-as-is",
        "--silent",
        "--show-error",
        "--output",
        "/dev/null",
        "--write-out",
        "%{http_code}",
        url,
    )
    status = process.stdout.read()
    if process.wait() != 0:
        raise RuntimeError(process.stderr.read())
    return status


requests = [
    ("GET", "https://github.com/modal-labs/modal-client"),
    ("POST", "https://github.com/modal-labs/modal-client"),
    ("GET", "https://github.com/modal-labs/modal-examples"),
    ("GET", "https://github.com/modal-labs/modal-client/../modal-examples"),
    ("GET", "https://example.com/"),
]
for method, url in requests:
    print(f"{method} {url} -> {request_status(method, url)}")

# The output should look like:

# ```
# GET https://github.com/modal-labs/modal-client -> 200
# POST https://github.com/modal-labs/modal-client -> 403
# GET https://github.com/modal-labs/modal-examples -> 403
# GET https://github.com/modal-labs/modal-client/../modal-examples -> 403
# GET https://example.com/ -> 200
# ```

# Terminating the Sandbox also terminates its Sidecars.

sandbox.terminate()
