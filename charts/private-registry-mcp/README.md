# private-registry-mcp

A companion Helm chart that deploys the MPC-server Private Registry MCP server alongside an existing SUSE Private Registry (Harbor) installation.

## TL;DR

```bash
helm upgrade --install registry-mcp ./charts/private-registry-mcp \
  --namespace mcp-system \
  --create-namespace \
  -f mcp-values.yaml
```

## Introduction

This chart deploys the [MPC-server Private Registry](../../README.md) MCP server, which bridges any MCP-speaking AI assistant to a Harbor-based private registry for vulnerability scanning, SBOM retrieval, and project/repository inspection.

The chart is independent of any SUSE Private Registry (Harbor) chart: it does not install or modify a registry, it only connects to one that is already running via its API URL. It builds no container image either; you supply one, see [Build the image](#build-the-image).

## Prerequisites

- Kubernetes 1.23+
- Helm 3.8+
- An existing SUSE Private Registry (Harbor) instance reachable from the cluster
- A container image for this MCP server, built and made available to the cluster nodes (see [Build the image](#build-the-image))

## Build the image

From the repository root:

```bash
docker build -t private-registry-mcp:local .
```

The chart does not publish or build an image. Import the local image into every
cluster node (for example `k3d image import private-registry-mcp:local -c
<cluster-name>`), or push it to a registry reachable by the nodes and set
`image.repository`, `image.tag`, and, if needed, `imagePullSecrets`.

## Installing the Chart

Create a namespace, or use an existing namespace you are authorized to manage:

```bash
kubectl create namespace mcp-system
```

Create the Secrets the chart requires. Use a unique, long random MCP bearer token:

```bash
read -rsp 'Registry password: ' REGISTRY_PASSWORD; printf '\n'
printf %s "$REGISTRY_PASSWORD" | kubectl -n mcp-system create secret generic registry-credentials --from-file=password=/dev/stdin
unset REGISTRY_PASSWORD

read -rsp 'MCP bearer token: ' MCP_AUTH_TOKEN; printf '\n'
printf %s "$MCP_AUTH_TOKEN" | kubectl -n mcp-system create secret generic mcp-auth --from-file=token=/dev/stdin
unset MCP_AUTH_TOKEN
```

Install the chart with a values file (see [Parameters](#parameters)):

```bash
helm upgrade --install registry-mcp ./charts/private-registry-mcp \
  --namespace mcp-system -f mcp-values.yaml
kubectl -n mcp-system rollout status deployment/registry-mcp-private-registry-mcp
```

The command deploys the MCP server on the Kubernetes cluster using the default configuration, overridden by the values in `mcp-values.yaml`. The [Parameters](#parameters) section lists the parameters that can be configured during installation.

> **Tip**: List all releases with `helm list`.

## Uninstalling the Chart

```bash
helm uninstall registry-mcp --namespace mcp-system
```

The command removes all the Kubernetes components associated with the chart, including the Deployment, Service, and Ingress (if enabled). It does not remove any Secret created outside the chart (`registry-credentials`, `mcp-auth`, `registry-ca`), so delete those separately if no longer needed.

## Parameters

### Image parameters

| Name                  | Description                                      | Value              |
| ---------------------- | ------------------------------------------------- | ------------------- |
| `image.repository`     | Image repository                                  | `private-registry-mcp` |
| `image.tag`             | Image tag                                         | `local`             |
| `image.pullPolicy`      | Image pull policy                                 | `IfNotPresent`      |
| `imagePullSecrets`      | Secrets with credentials to pull the image        | `[]`                |

### Registry connection parameters

| Name                      | Description                                                                 | Value   |
| -------------------------- | ---------------------------------------------------------------------------- | ------- |
| `registry.url`              | URL of the existing Private Registry (Harbor) instance. Required.           | `""`    |
| `registry.username`         | Username the MCP server authenticates to the registry with. Required.      | `""`    |
| `registry.existingSecret`   | Name of an existing Secret holding the registry password. Required.        | `""`    |
| `registry.passwordKey`      | Key within `registry.existingSecret` that contains the password.           | `password` |
| `registry.caSecret`         | Name of an existing Secret with a private CA certificate under `ca.crt`, added to the image's trust store. | `""`    |

### MCP authentication parameters

| Name                  | Description                                                                 | Value   |
| ---------------------- | ------------------------------------------------------------------------------ | ------- |
| `auth.existingSecret`   | Name of an existing Secret holding the MCP bearer token. Required.            | `""`    |
| `auth.tokenKey`         | Key within `auth.existingSecret` that contains the bearer token.             | `token` |

### Crane (upstream registry) parameters

| Name                     | Description                                                                                                  | Value |
| ------------------------- | --------------------------------------------------------------------------------------------------------------- | ----- |
| `crane.existingSecret`     | Name of an existing `.dockerconfigjson` Secret used by `crane` to authenticate to an upstream registry during patched-image searches. Separate from `imagePullSecrets`. | `""`  |

### Ingress parameters

| Name                   | Description                                                        | Value   |
| ----------------------- | --------------------------------------------------------------------- | ------- |
| `ingress.enabled`        | Enable an Ingress resource                                          | `false` |
| `ingress.className`      | IngressClass to use                                                  | `""`    |
| `ingress.host`           | Hostname for the Ingress. Required when `ingress.enabled` is `true`. | `""`    |
| `ingress.tlsSecret`      | Name of an existing TLS Secret for the host. Required when `ingress.enabled` is `true`. | `""`    |
| `ingress.annotations`    | Additional annotations for the Ingress resource (for example, controller-specific settings) | `{}`    |

### Resource parameters

| Name                     | Description                   | Value   |
| ------------------------- | -------------------------------- | ------- |
| `resources.requests.cpu`   | CPU resource requests          | `50m`   |
| `resources.requests.memory`| Memory resource requests       | `64Mi`  |
| `resources.limits.cpu`     | CPU resource limits            | `500m`  |
| `resources.limits.memory`  | Memory resource limits         | `256Mi` |

Specify parameters using the `--set key=value[,key=value]` argument to `helm install` or `helm upgrade`, or provide a YAML file with `-f/--values`, as shown above.

## Configuration and installation details

### Credentials and secrets

`registry.url` and `registry.username` are plain values; the registry password and the MCP bearer token must come from existing Secrets (`registry.existingSecret` and `auth.existingSecret`) so that neither is stored in Helm values or release history. Create a dedicated registry account scoped to only the permissions needed for the tools you intend to use: the server uses one account for all MCP clients, and the bearer token authorizes MCP access, not per-user Harbor authorization.

Secret values are read at pod startup. After rotating credentials or a CA certificate, restart the Deployment:

```bash
kubectl -n mcp-system rollout restart deployment/registry-mcp-private-registry-mcp
```

### TLS to the private registry

TLS certificate verification happens in-process and cannot be disabled through this chart. For a registry with a private CA, create a Secret with the CA certificate under the `ca.crt` key and reference it as `registry.caSecret`:

```bash
kubectl -n mcp-system create secret generic registry-ca --from-file=ca.crt=./ca.crt
```

The CA is added to the image's system trust store; it does not disable verification.

### Exposing the MCP server (Ingress)

Set `ingress.enabled: true` together with `ingress.host` and `ingress.tlsSecret` (a TLS Secret for that host must already exist in the chart's namespace). The chart requires both when Ingress is enabled, but cannot verify that the controller enforces HTTPS or that the certificate is trusted.

```yaml
ingress:
  enabled: true
  className: nginx
  host: mcp.example.com
  tlsSecret: mcp-tls
  annotations: {}
```

Use a controller that supports Streamable HTTP, long-lived connections, and forwards the `Authorization` and `Mcp-Session-Id` headers, and configure it to reject plain HTTP rather than only redirect it — a bearer token sent over HTTP is already exposed. The resulting endpoint is `https://mcp.example.com/mpc-spr`.

### `crane` authentication

If `find_patched_image` or other `crane`-backed operations need to authenticate to an upstream registry, set `crane.existingSecret` to an existing Secret containing a `.dockerconfigjson` key. This is independent of `imagePullSecrets`, which only authorizes the kubelet to pull the MCP server's own image.

### High availability

The chart always runs a single replica with a `Recreate` rollout strategy, because MCP sessions are held in the server process rather than externally. A restart or upgrade ends existing sessions; clients must reconnect and re-initialize. This is not configurable.

### Probes

The readiness probe (`/readyz`) calls the registry's health API (cached for a few seconds) and takes the pod out of service when the registry is unreachable or unhealthy. The liveness probe (`/healthz`) only confirms the process is serving. Neither endpoint requires the MCP bearer token.

See the [container and Helm deployment guide](../../docs/container-deployment.md) for a complete walkthrough, including standalone Docker usage.
