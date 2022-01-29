package response

import (
	"fmt"
	"net/http"
	"strings"
)

func HttpsRedirectMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme := r.URL.Scheme
		if strings.ToLower(scheme) == "http" {
			http.Redirect(w, r, fmt.Sprintf("https://%s%s", r.Host, r.URL.Path), http.StatusMovedPermanently)
			return
		}
		next.ServeHTTP(w, r)
	})
}
