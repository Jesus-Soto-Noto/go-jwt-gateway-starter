package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Jesus-Soto-Noto/go-jwt-gateway-starter/internal/auth"
)

type ctxKey string

const claimsKey ctxKey = "jwt_claims"

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func requireRoles(secret []byte, roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
				return
			}

			raw := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := auth.VerifyHS256(raw, secret, time.Now())
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
				return
			}

			if err := claims.HasAnyRole(roles...); err != nil {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
				return
			}

			r.Header.Set("X-User-Sub", claims.Sub)
			r.Header.Set("X-Region-Scope", claims.RegionScope)
			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func newUpstreamProxy(rawTarget string) http.Handler {
	target, err := url.Parse(rawTarget)
	if err != nil {
		log.Fatalf("invalid upstream url %q: %v", rawTarget, err)
	}
	return httputil.NewSingleHostReverseProxy(target)
}

func main() {
	port := envOr("APP_PORT", "8080")
	jwtSecret := []byte(envOr("JWT_SECRET", "dev-gateway-secret"))
	coreServiceURL := envOr("CORE_SERVICE_URL", "http://localhost:8081")

	mux := http.NewServeMux()

	// Public unauthenticated endpoints (health & public support configuration)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "healthy",
			"service": "go-jwt-gateway",
		})
	})

	// Protected upstream routes with RBAC & 2FA TOTP enforcement
	reportsGuard := requireRoles(jwtSecret, "regional_coordinator", "analyst")
	mux.Handle("/api/v1/reports/", reportsGuard(newUpstreamProxy(coreServiceURL)))

	log.Printf("API Gateway listening on :%s -> upstream %s", port, coreServiceURL)
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
