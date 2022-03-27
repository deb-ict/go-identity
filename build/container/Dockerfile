
# Build
FROM golang:1.17.6-alpine3.15 as build
WORKDIR /src

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /app/go-identity cmd/server/main.go

# Runtime
FROM scratch
WORKDIR /app
COPY --from=build /app/go-identity .
COPY configs/*.yaml /etc/go-identity/

EXPOSE 80
ENTRYPOINT [ "/app/go-identity" ]