package ginrouter_test

import (
	"net/http"
	"testing"

	"github.com/deb-ict/go-identity/pkg/router"
	"github.com/deb-ict/go-identity/pkg/router/routertest"
	ginrouter "github.com/deb-ict/go-identity/router/gin"
	"github.com/gin-gonic/gin"
)

func TestConformance(t *testing.T) {
	gin.SetMode(gin.TestMode)
	routertest.Run(t, func(t *testing.T) (router.Router, http.Handler) {
		engine := gin.New()
		return ginrouter.New(engine), engine
	})
}
