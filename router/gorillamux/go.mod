module github.com/deb-ict/go-identity/router/gorillamux

go 1.24.0

toolchain go1.24.7

require (
	github.com/deb-ict/go-identity v0.0.0
	github.com/gorilla/mux v1.8.1
)

replace github.com/deb-ict/go-identity => ../..
