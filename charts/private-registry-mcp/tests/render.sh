#!/usr/bin/env bash
set -euo pipefail

chart="$(dirname "$0")/.."
values=(
  --set registry.url=https://registry.example
  --set registry.username=robot
  --set registry.existingSecret=registry-creds
  --set auth.existingSecret=mcp-auth
)

default="$(helm template test "$chart" "${values[@]}")"
grep -q 'type: ClusterIP' <<<"$default"
grep -q 'replicas: 1' <<<"$default"
grep -q 'type: Recreate' <<<"$default"
grep -q 'name: "registry-creds"' <<<"$default"
grep -q 'name: "mcp-auth"' <<<"$default"
grep -q 'path: /readyz' <<<"$default"
grep -q 'path: /healthz' <<<"$default"
grep -q 'cpu: 50m' <<<"$default"
grep -q 'memory: 256Mi' <<<"$default"
if grep -q '^kind: Ingress$' <<<"$default"; then
  echo "unexpected default ingress" >&2
  exit 1
fi

configured="$(helm template test "$chart" "${values[@]}" \
  --set registry.caSecret=registry-ca \
  --set crane.existingSecret=upstream-credentials \
  --set ingress.enabled=true --set ingress.host=mcp.example.com --set ingress.tlsSecret=mcp-tls)"
grep -q '^kind: Ingress$' <<<"$configured"
grep -q 'secretName: "mcp-tls"' <<<"$configured"
grep -q 'secretName: "registry-ca"' <<<"$configured"
grep -q '/etc/ssl/certs:/etc/mcp-ca' <<<"$configured"
grep -q 'secretName: "upstream-credentials"' <<<"$configured"
grep -q 'name: DOCKER_CONFIG' <<<"$configured"

if helm template test "$chart" "${values[@]}" \
  --set ingress.enabled=true --set ingress.host=mcp.example.com >/dev/null 2>&1; then
  echo "ingress without TLS secret was accepted" >&2
  exit 1
fi
if helm template test "$chart" >/dev/null 2>&1; then
  echo "missing required registry settings were accepted" >&2
  exit 1
fi
echo "Helm rendering tests passed"
