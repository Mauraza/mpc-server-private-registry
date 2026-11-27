FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/private-registry-mcp .
RUN CGO_ENABLED=0 go install github.com/google/go-containerregistry/cmd/crane@v0.20.6

FROM alpine:3.23
RUN apk add --no-cache ca-certificates
COPY --from=build /out/private-registry-mcp /usr/local/bin/private-registry-mcp
COPY --from=build /go/bin/crane /usr/local/bin/crane
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/private-registry-mcp"]
