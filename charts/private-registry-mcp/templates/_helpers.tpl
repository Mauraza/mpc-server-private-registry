{{- define "private-registry-mcp.fullname" -}}
{{- printf "%s-private-registry-mcp" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "private-registry-mcp.labels" -}}
app.kubernetes.io/name: private-registry-mcp
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
{{- end -}}
