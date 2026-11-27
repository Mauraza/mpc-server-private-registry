# Container and companion Helm chart

The MCP server can run next to an existing SUSE Private Registry (SPR) without
changing the SPR chart. The companion chart is a separate Helm release and
connects to the registry over its configured API URL. For a local MCP client,
running the existing Go/stdio configuration is simpler if Go and `crane` are
already installed. A standalone container is another option; Kubernetes and
Helm are not required.

## Build the image

From the repository root:

```bash
docker build -t private-registry-mcp:local .
```

The image includes `crane` for patched-image searches and runs as a non-root
user. It supports the existing HTTP and `--stdio` modes. The image is local to
the Docker daemon: before installing the chart, import it into every Kubernetes
node using your cluster's image-loading mechanism, or tag and push it to a
registry accessible to the nodes and set `image.repository`, `image.tag`, and,
if needed, `imagePullSecrets` in the chart. The chart does not publish an image.
For example, a k3d cluster can load the local image with
`k3d image import private-registry-mcp:local -c <cluster-name>`.

## Configuration and credentials

These environment variables provide defaults for existing command-line flags:

| Environment variable | Flag |
| --- | --- |
| `PRIVATE_REGISTRY_URL` | `--private-registry-url` |
| `PRIVATE_REGISTRY_USERNAME` | `--private-registry-username` |
| `PRIVATE_REGISTRY_PASSWORD` | `--private-registry-password` |
| `MCP_AUTH_TOKEN` | `--mcp-auth-token` |

An explicitly supplied flag takes precedence over its environment variable,
including an empty flag value. With neither, the existing flag defaults apply.
Environment variables and Kubernetes Secrets are still accessible to authorized
container/cluster administrators; restrict access accordingly. Avoid passing
passwords and tokens as command-line flags or storing them in Helm values.

Create a dedicated registry account with only the permissions needed for the
tools you intend to use. The server uses this one account for all clients; its
MCP bearer token is a separate credential and does not provide per-user Harbor
authorization. Some tools change registry state: scanning triggers scans,
`create_project` creates a project, and `find_patched_image` can create proxy
projects and trigger scans. Limit who receives the MCP token and configure
human approval where appropriate.

## Install the chart

Create a namespace, or use an existing namespace you are authorized to manage.
The following examples use `mcp-system`:

```bash
kubectl create namespace mcp-system
```

Create two Secrets there, using a unique, long random MCP bearer token. These
commands read values without echoing them and pass them to `kubectl` via
standard input:

```bash
read -rsp 'Registry password: ' REGISTRY_PASSWORD; printf '\n'
printf %s "$REGISTRY_PASSWORD" | kubectl -n mcp-system create secret generic registry-credentials --from-file=password=/dev/stdin
unset REGISTRY_PASSWORD

read -rsp 'MCP bearer token: ' MCP_AUTH_TOKEN; printf '\n'
printf %s "$MCP_AUTH_TOKEN" | kubectl -n mcp-system create secret generic mcp-auth --from-file=token=/dev/stdin
unset MCP_AUTH_TOKEN
```

Use the externally configured SPR URL, or an internal URL that is reachable
from the MCP pod and matches the registry certificate. For a private CA, create
a Secret containing its PEM certificate:

```bash
kubectl -n mcp-system create secret generic registry-ca --from-file=ca.crt=./ca.crt
```

For example, save the following as a local values file; replace the URL and
username and omit `caSecret` if the system trust store already trusts SPR:

```yaml
image:
  repository: private-registry-mcp
  tag: local
  pullPolicy: IfNotPresent
registry:
  url: https://registry.example.com
  username: registry-user
  existingSecret: registry-credentials
  passwordKey: password
  caSecret: registry-ca
auth:
  existingSecret: mcp-auth
  tokenKey: token
```

```bash
helm upgrade --install registry-mcp ./charts/private-registry-mcp \
  --namespace mcp-system -f mcp-values.yaml
kubectl -n mcp-system rollout status deployment/registry-mcp-private-registry-mcp
```

The optional CA is added to the image's system trust; it does not disable TLS
verification. Secret values are read at pod startup: after changing credentials
or a CA, restart the Deployment. The liveness probe (`/healthz`) only confirms
the process is serving; the readiness probe (`/readyz`) calls the registry's
health API (result cached for a few seconds) and fails the pod out of service
when the registry is unreachable or unhealthy. Neither endpoint requires the
MCP bearer token.

CPU/memory `resources` default to modest requests/limits in `values.yaml`;
override them for heavier scan workloads.

If `crane` must authenticate to an upstream registry during patched-image
searches, set `crane.existingSecret` to a Secret in the chart namespace with a
`.dockerconfigjson` key containing Docker registry credentials. This is
separate from `imagePullSecrets`, which only authenticate Kubernetes image
pulls. Docker credential-helper executables are not included in the image;
provide credentials that `crane` can read directly from the config.

The chart uses one replica and a non-overlapping rollout because MCP sessions
are held in the server process. A restart or upgrade ends existing sessions;
clients must reconnect and initialize again. The ClusterIP endpoint is
`http://registry-mcp-private-registry-mcp.mcp-system.svc:8080/mpc-spr` for
clients on a trusted cluster network. The server itself uses HTTP: a bearer
token does not encrypt traffic. Use a protected network or TLS termination.

## Optional TLS ingress

Create a TLS Secret in the chart namespace for the MCP hostname and add these
values to the file before installing or upgrading:

```yaml
ingress:
  enabled: true
  className: nginx
  host: mcp.example.com
  tlsSecret: mcp-tls
  annotations: {}
```

Configure DNS and an ingress controller that supports Streamable HTTP,
long-lived connections, and forwarding `Authorization` and `Mcp-Session-Id`
headers. Configure the controller to reject or disable plain HTTP access, not
just redirect it: a token sent over HTTP is already exposed. Controller-specific
settings belong in `ingress.annotations` or the controller configuration.
The chart requires both host and TLS Secret when ingress is enabled, but cannot
verify that the controller enforces HTTPS or that the certificate is trusted.

The endpoint is `https://mcp.example.com/mpc-spr`. Use the same MCP token in
the client's `Authorization: Bearer <token>` header. Verify MCP initialization
and then a registry tool such as `get_health`; initialization alone does not
check the registry credentials or TLS connection.

## Standalone Docker

Set the four environment variables above in your shell without placing
credentials in the command history. For a local HTTP client:

```bash
docker run --rm -p 127.0.0.1:8080:8080 \
  -e PRIVATE_REGISTRY_URL -e PRIVATE_REGISTRY_USERNAME \
  -e PRIVATE_REGISTRY_PASSWORD -e MCP_AUTH_TOKEN \
  private-registry-mcp:local --host 0.0.0.0
```

Even though the host port is loopback-only, the server listens on a
non-loopback container interface and requires the MCP token. For a client that
launches a stdio process, use `docker run --rm -i` with the registry environment
variables and append `--stdio` instead of publishing a port. A non-system
registry CA can be mounted in a directory and included alongside
`/etc/ssl/certs` in `SSL_CERT_DIR`; keep TLS verification enabled.
