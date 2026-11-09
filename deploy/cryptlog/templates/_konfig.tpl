{{- define "cryptlog.zahl" -}}
{{- printf "%d" (int .) -}}
{{- end -}}

{{- define "cryptlog.warte" -}}
{{- $ms := int . -}}
{{- if eq (mod $ms 1000) 0 -}}{{ div $ms 1000 }}s{{- else -}}{{ $ms }}ms{{- end -}}
{{- end -}}

{{- define "cryptlog.ziel" -}}
{{- if eq .art "platte" -}}
ziel = platte
wurzel = /var/lib/cryptlog/ziel
{{- else -}}
ziel = s3
endpunkt = {{ .endpunkt }}
bucket = {{ .bucket }}
region = {{ .region }}
zugang = /run/cryptlog/geheim/zugang
geheimnis = /run/cryptlog/geheim/geheimnis
{{- end -}}
{{- end -}}

{{- define "cryptlog.schwellen" -}}
frist = {{ include "cryptlog.zahl" .fristS }}s
puffer = {{ include "cryptlog.zahl" .puffer }}
puffer_warte = {{ include "cryptlog.warte" .pufferWarteMs }}
segment = {{ include "cryptlog.zahl" .segment }}
segment_warte = {{ include "cryptlog.zahl" .segmentWarteS }}s
klasse = {{ include "cryptlog.zahl" .klasse }}
gruppe = {{ include "cryptlog.zahl" .gruppeS }}s
einzel = {{ include "cryptlog.zahl" .einzelS }}s
sonstige = {{ include "cryptlog.zahl" .sonstigeS }}s
{{- end -}}

{{- define "cryptlog.fassung" -}}
{{- $digest := .digest -}}
{{- with .version }}
version = {{ . }}
digest = {{ $digest }}
{{- end }}
{{- end -}}

{{- define "cryptlog.schreiben.conf" -}}
{{- $root := .root -}}
instanz = {{ .instanz }}
spool = /var/lib/cryptlog/spool
ereignis = 0.0.0.0:{{ $root.Values.schreiben.ereignisPort }}
metrik = 0.0.0.0:{{ $root.Values.schreiben.metrikPort }}
{{ include "cryptlog.ziel" $root.Values.ziel }}
plattform = /run/cryptlog/geheim/plattform
index = /run/cryptlog/geheim/index
signatur = /run/cryptlog/geheim/signatur
mandanten = /var/lib/cryptlog/mandanten
spool_grenze = {{ include "cryptlog.zahl" $root.Values.grenzen.spoolGrenze }}
{{ include "cryptlog.schwellen" $root.Values.grenzen }}
{{ include "cryptlog.fassung" (dict "version" $root.Values.build.version "digest" $root.Values.image.digest) }}
{{- end -}}

{{- define "cryptlog.suchen.conf" -}}
{{- $root := .root -}}
instanz = {{ .instanz }}
protokoll = /var/lib/cryptlog/protokoll/gesehen
suche = 0.0.0.0:{{ $root.Values.suchen.suchePort }}
metrik = 0.0.0.0:{{ $root.Values.suchen.metrikPort }}
{{ include "cryptlog.ziel" $root.Values.ziel }}
index = /run/cryptlog/geheim/index
signatur = /run/cryptlog/geheim/signatur
mandanten = /var/lib/cryptlog/mandanten
{{ include "cryptlog.schwellen" $root.Values.grenzen }}
{{ include "cryptlog.fassung" (dict "version" $root.Values.build.version "digest" $root.Values.image.digest) }}
{{- end -}}
