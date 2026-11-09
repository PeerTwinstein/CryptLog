{{- define "cryptlog.epoche" -}}
{{- $d := int .dauer -}}
{{- if or (lt $d (int .min)) (gt $d (int .max)) (ne (mod (int .tag) $d) 0) -}}
{{- fail (printf "Chart: %s" .feld) -}}
{{- end -}}
{{- end -}}

{{- define "cryptlog.ports" -}}
{{- $a := int .a -}}
{{- $b := int .b -}}
{{- if or (lt $a 1024) (gt $a 65535) (lt $b 1024) (gt $b 65535) (eq $a $b) -}}
{{- fail "Chart: Port" -}}
{{- end -}}
{{- end -}}

{{- define "cryptlog.uid" -}}
{{- $uid := int . -}}
{{- if or (lt $uid 1) (gt $uid 65535) -}}
{{- fail "Chart: Konto" -}}
{{- end -}}
{{- end -}}

{{- define "cryptlog.claim" -}}
{{- if or (gt (len .) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" .)) -}}
{{- fail "Chart: Anspruch" -}}
{{- end -}}
{{- end -}}

{{- define "cryptlog.geheim" -}}
{{- if or (gt (len .name) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" .name)) -}}
{{- fail (printf "Chart: %s" .feld) -}}
{{- end -}}
{{- if or (not .key) (gt (len .key) 253) (contains "/" .key) (contains ".." .key) -}}
{{- fail (printf "Chart: %s" .feld) -}}
{{- end -}}
{{- end -}}

{{- define "cryptlog.namensraum" -}}
{{- if or (gt (len .) 63) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" .)) -}}
{{- fail "Chart: Namensraum" -}}
{{- end -}}
{{- end -}}

{{- define "cryptlog.fassungpruefen" -}}
{{- $v := .version -}}
{{- if $v -}}
{{- if or (gt (len $v) 128) (contains "\"" $v) (contains "\\" $v) (not (regexMatch "^[!-~]+$" $v)) -}}
{{- fail "Chart: Fassung" -}}
{{- end -}}
{{- if or (gt (len .digest) 128) (contains "\"" .digest) (contains "\\" .digest) -}}
{{- fail "Chart: Fassung" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "cryptlog.grenzen" -}}
{{- if and (not .Values.schreiben.enabled) (not .Values.suchen.enabled) -}}
{{- fail "Chart: Komponente" -}}
{{- end -}}
{{- if or (not .Values.image.repository) (contains "@" .Values.image.repository) (contains " " .Values.image.repository) -}}
{{- fail "Chart: Image" -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" .Values.image.digest) -}}
{{- fail "Chart: Digest" -}}
{{- end -}}
{{- if .Values.image.tag -}}
{{- fail "Chart: Tag" -}}
{{- end -}}
{{- include "cryptlog.fassungpruefen" (dict "version" .Values.build.version "digest" .Values.image.digest) -}}
{{- $pufferMin := 65536 -}}
{{- $pufferMax := 8388608 -}}
{{- $warteMin := 10 -}}
{{- $warteMax := 1000 -}}
{{- $segmentMin := 262144 -}}
{{- $segmentMax := 33554432 -}}
{{- $segmentWarteMin := 10 -}}
{{- $segmentWarteMax := 300 -}}
{{- $epocheMin := 900 -}}
{{- $epocheMax := 28800 -}}
{{- $tag := 86400 -}}
{{- $beendenZusatz := 30 -}}
{{- $puffer := int .Values.grenzen.puffer -}}
{{- $segment := int .Values.grenzen.segment -}}
{{- $warte := int .Values.grenzen.pufferWarteMs -}}
{{- $segmentWarte := int .Values.grenzen.segmentWarteS -}}
{{- $klasse := int .Values.grenzen.klasse -}}
{{- if or (lt $puffer $pufferMin) (gt $puffer $pufferMax) -}}
{{- fail "Chart: Puffer" -}}
{{- end -}}
{{- if or (lt $warte $warteMin) (gt $warte $warteMax) -}}
{{- fail "Chart: Puffer" -}}
{{- end -}}
{{- if or (lt $segment $segmentMin) (gt $segment $segmentMax) -}}
{{- fail "Chart: Segment" -}}
{{- end -}}
{{- if or (lt $segmentWarte $segmentWarteMin) (gt $segmentWarte $segmentWarteMax) -}}
{{- fail "Chart: Segment" -}}
{{- end -}}
{{- $klasseOK := false -}}
{{- range list 262144 1048576 4194304 16777216 33554432 -}}
{{- if eq (int .) $klasse }}{{ $klasseOK = true }}{{ end -}}
{{- end -}}
{{- if not $klasseOK -}}
{{- fail "Chart: Klasse" -}}
{{- end -}}
{{- if lt (int .Values.grenzen.spoolGrenze) $klasse -}}
{{- fail "Chart: Spool" -}}
{{- end -}}
{{- if le (int .Values.grenzen.fristS) $segmentWarte -}}
{{- fail "Chart: Frist" -}}
{{- end -}}
{{- if lt (int .Values.beendenS) (add $segmentWarte $beendenZusatz) -}}
{{- fail "Chart: Beenden" -}}
{{- end -}}
{{- include "cryptlog.epoche" (dict "dauer" .Values.grenzen.gruppeS "min" $epocheMin "max" $epocheMax "tag" $tag "feld" "Gruppe") -}}
{{- include "cryptlog.epoche" (dict "dauer" .Values.grenzen.einzelS "min" $epocheMin "max" $epocheMax "tag" $tag "feld" "Einzel") -}}
{{- include "cryptlog.epoche" (dict "dauer" .Values.grenzen.sonstigeS "min" $epocheMin "max" $epocheMax "tag" $tag "feld" "Sonstige") -}}
{{- $summe := add $puffer $segment -}}
{{- if eq .Values.ziel.art "platte" -}}
{{- if or .Values.ziel.endpunkt .Values.ziel.bucket .Values.ziel.region .Values.ziel.zugang.name .Values.ziel.geheimnis.name -}}
{{- fail "Chart: Ziel" -}}
{{- end -}}
{{- include "cryptlog.claim" .Values.ziel.claim -}}
{{- else if eq .Values.ziel.art "s3" -}}
{{- if .Values.ziel.claim -}}
{{- fail "Chart: Ziel" -}}
{{- end -}}
{{- if not (regexMatch "^https?://[A-Za-z0-9._:-]+/?$" .Values.ziel.endpunkt) -}}
{{- fail "Chart: Ziel" -}}
{{- end -}}
{{- if or (not .Values.ziel.bucket) (contains "/" .Values.ziel.bucket) (contains " " .Values.ziel.bucket) (not .Values.ziel.region) (contains " " .Values.ziel.region) -}}
{{- fail "Chart: Ziel" -}}
{{- end -}}
{{- include "cryptlog.geheim" (dict "name" .Values.ziel.zugang.name "key" .Values.ziel.zugang.key "feld" "Zugang") -}}
{{- include "cryptlog.geheim" (dict "name" .Values.ziel.geheimnis.name "key" .Values.ziel.geheimnis.key "feld" "Geheimnis") -}}
{{- else -}}
{{- fail "Chart: Ziel" -}}
{{- end -}}
{{- include "cryptlog.claim" .Values.mandanten.claim -}}
{{- if and (eq .Values.ziel.art "platte") (eq .Values.ziel.claim .Values.mandanten.claim) -}}
{{- fail "Chart: Ziel" -}}
{{- end -}}
{{- if .Values.schreiben.enabled -}}
{{- if le (int .Values.schreiben.speicher) $summe -}}
{{- fail "Chart: Speicher" -}}
{{- end -}}
{{- include "cryptlog.uid" .Values.schreiben.uid -}}
{{- include "cryptlog.ports" (dict "a" .Values.schreiben.ereignisPort "b" .Values.schreiben.metrikPort) -}}
{{- if not .Values.schreiben.instanzen -}}
{{- fail "Chart: Instanz" -}}
{{- end -}}
{{- if or .Values.schreiben.indexPrivat (index .Values.schreiben.geheim "privat") -}}
{{- fail "Chart: privater Index-Schlüssel" -}}
{{- end -}}
{{- $gesehen := dict -}}
{{- $kurz := dict -}}
{{- range .Values.schreiben.instanzen -}}
{{- if or (not (regexMatch "^[0-9a-f]{32}$" .)) (eq . "00000000000000000000000000000000") -}}
{{- fail "Chart: Instanz" -}}
{{- end -}}
{{- $k := substr 0 12 . -}}
{{- if or (index $gesehen .) (index $kurz $k) -}}
{{- fail "Chart: Instanz" -}}
{{- end -}}
{{- $_ := set $gesehen . "da" -}}
{{- $_ := set $kurz $k "da" -}}
{{- if gt (len (printf "%s-schreiben-%s" $.Release.Name $k)) 63 -}}
{{- fail "Chart: Name" -}}
{{- end -}}
{{- end -}}
{{- include "cryptlog.geheim" (dict "name" .Values.schreiben.geheim.plattform.name "key" .Values.schreiben.geheim.plattform.key "feld" "Plattform-KEK") -}}
{{- include "cryptlog.geheim" (dict "name" .Values.schreiben.geheim.cache.name "key" .Values.schreiben.geheim.cache.key "feld" "Cache-Schlüssel") -}}
{{- include "cryptlog.geheim" (dict "name" .Values.schreiben.geheim.index.name "key" .Values.schreiben.geheim.index.key "feld" "Index-Schlüssel") -}}
{{- include "cryptlog.geheim" (dict "name" .Values.schreiben.geheim.signatur.name "key" .Values.schreiben.geheim.signatur.key "feld" "Signatur") -}}
{{- if not .Values.schreiben.aufrufer -}}
{{- fail "Chart: Aufrufer" -}}
{{- end -}}
{{- range .Values.schreiben.aufrufer -}}
{{- include "cryptlog.namensraum" .namespace -}}
{{- end -}}
{{- include "cryptlog.namensraum" .Values.schreiben.ueberwachung -}}
{{- end -}}
{{- if .Values.suchen.enabled -}}
{{- if le (int .Values.suchen.speicher) $summe -}}
{{- fail "Chart: Speicher" -}}
{{- end -}}
{{- if ne (int .Values.suchen.replicas) 1 -}}
{{- fail "Chart: Replica" -}}
{{- end -}}
{{- include "cryptlog.uid" .Values.suchen.uid -}}
{{- include "cryptlog.ports" (dict "a" .Values.suchen.suchePort "b" .Values.suchen.metrikPort) -}}
{{- if or (not (regexMatch "^[0-9a-f]{32}$" .Values.suchen.instanz)) (eq .Values.suchen.instanz "00000000000000000000000000000000") -}}
{{- fail "Chart: Instanz" -}}
{{- end -}}
{{- if gt (len (printf "%s-suchen" $.Release.Name)) 63 -}}
{{- fail "Chart: Name" -}}
{{- end -}}
{{- if or .Values.suchen.plattform .Values.suchen.cache (index .Values.suchen.geheim "plattform") (index .Values.suchen.geheim "cache") -}}
{{- fail "Chart: Suchprozess" -}}
{{- end -}}
{{- include "cryptlog.geheim" (dict "name" .Values.suchen.geheim.index.name "key" .Values.suchen.geheim.index.key "feld" "Index-Schlüssel") -}}
{{- include "cryptlog.geheim" (dict "name" .Values.suchen.geheim.signatur.name "key" .Values.suchen.geheim.signatur.key "feld" "Signatur") -}}
{{- if and .Values.schreiben.enabled (eq .Values.schreiben.geheim.index.name .Values.suchen.geheim.index.name) (eq .Values.schreiben.geheim.index.key .Values.suchen.geheim.index.key) -}}
{{- fail "Chart: privater Index-Schlüssel" -}}
{{- end -}}
{{- if not .Values.suchen.weg -}}
{{- fail "Chart: Weg" -}}
{{- end -}}
{{- range .Values.suchen.weg -}}
{{- include "cryptlog.namensraum" .namespace -}}
{{- end -}}
{{- include "cryptlog.namensraum" .Values.suchen.ueberwachung -}}
{{- end -}}
{{- end -}}
