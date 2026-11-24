{{/* Copyright (c) 2026 Sudheer Kumar. SPDX-License-Identifier: AGPL-3.0-only. */}}
{{- define "myelin.name" -}}{{ .Release.Name }}-myelin{{- end -}}
{{- define "myelin.labels" -}}
app.kubernetes.io/name: myelin
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "myelin.selector" -}}
app.kubernetes.io/name: myelin
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: api
{{- end -}}
{{- define "myelin.image" -}}
{{ .Values.image.repository }}{{ if .Values.image.digest }}@{{ .Values.image.digest }}{{ else }}:{{ .Values.image.tag }}{{ end }}
{{- end -}}
{{- define "myelin.serviceAccount" -}}
{{ default (include "myelin.name" .) .Values.serviceAccount.name }}
{{- end -}}
{{- define "myelin.podSecurity" -}}
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
fsGroup: 10001
seccompProfile: { type: RuntimeDefault }
{{- end -}}
{{- define "myelin.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
privileged: false
capabilities: { drop: [ALL] }
{{- end -}}
{{- define "myelin.secretEnv" -}}
{{- range $k, $v := .Values.secrets.keys }}
- name: {{ $v }}
  valueFrom: { secretKeyRef: { name: {{ $.Values.secrets.name }}, key: {{ $v }} } }
{{- end }}
{{- end -}}
