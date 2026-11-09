# Image der Plattform. Es enthält das Programm, keine Shell und kein Secret.
# Das Fenster ist in diesem Build nicht enthalten.

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -tags cryptlog_image -ldflags='-s -w' -o /out/cryptlog ./cmd/cryptlog \
	&& chmod 0555 /out/cryptlog

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cryptlog /cryptlog
USER 65532:65532
ENTRYPOINT ["/cryptlog"]
