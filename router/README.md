# Router adapters

The identity server registers its routes on a `router.Router`
(`github.com/deb-ict/go-identity/pkg/router`). Routes use canonical `{name}`
placeholders (for example `/api/clients/{id}`) and handlers read path parameters
with `router.Param(r, "id")`.

The net/http `ServeMux` adapter is part of the core (`router.NewServeMux()`).
Adapters for third party routers live in separate Go modules so the core module has
no dependency on them. Every adapter passes the `pkg/router/routertest` conformance suite.

| Router | Module | Package | Constructor |
| --- | --- | --- | --- |
| [chi](https://github.com/go-chi/chi) | `github.com/deb-ict/go-identity/router/chi` | `chirouter` | `New(r chi.Router) router.Router` |
| [gin](https://github.com/gin-gonic/gin) | `github.com/deb-ict/go-identity/router/gin` | `ginrouter` | `New(r gin.IRoutes) router.Router` |
| [httprouter](https://github.com/julienschmidt/httprouter) | `github.com/deb-ict/go-identity/router/httprouter` | `httprouteradapter` | `New(r *httprouter.Router) router.Router` |
| [gorilla/mux](https://github.com/gorilla/mux) | `github.com/deb-ict/go-identity/router/gorillamux` | `muxrouter` | `New(r *mux.Router) router.Router` |
| [echo](https://github.com/labstack/echo) | `github.com/deb-ict/go-identity/router/echo` | `echorouter` | `New(r echorouter.Routes) router.Router` (`*echo.Echo` or `*echo.Group`) |

## Usage

In the snippets below, `register` is whatever function registers the identity
server routes on a `router.Router`.

### chi

```go
r := chi.NewRouter()
register(chirouter.New(r))
http.ListenAndServe(":8080", r)
```

### gin

```go
engine := gin.New()
register(ginrouter.New(engine)) // or ginrouter.New(engine.Group("/identity"))
engine.Run(":8080")
```

### httprouter

```go
r := httprouter.New()
register(httprouteradapter.New(r))
http.ListenAndServe(":8080", r)
```

### gorilla/mux

```go
r := mux.NewRouter()
register(muxrouter.New(r)) // or muxrouter.New(r.PathPrefix("/identity").Subrouter())
http.ListenAndServe(":8080", r)
```

### echo

```go
e := echo.New()
register(echorouter.New(e)) // or echorouter.New(e.Group("/identity"))
e.Start(":8080")
```

To mount the routes under a prefix on any router, you can also use
`router.WithPrefix(adapter, "/identity")`. To wrap all handlers, use `router.WithMiddleware`.
