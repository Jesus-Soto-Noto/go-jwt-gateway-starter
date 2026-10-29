# Go JWT API Gateway & RBAC Middleware Blueprint

![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)
![CI](https://github.com/Jesus-Soto-Noto/go-jwt-gateway-starter/actions/workflows/ci.yml/badge.svg)
![Docker](https://img.shields.io/badge/Docker-Multi--Stage-2496ED?logo=docker&logoColor=white)
![Zero Deps](https://img.shields.io/badge/Stdlib-100%25_Native-10B981)

Arquitectura ligera de **API Gateway en Go (Golang)** construida 100% sobre la librería estándar (`net/http`, `httputil.ReverseProxy`, `crypto/hmac`) para enrutar microservicios con validación de tokens **JWT**, control de acceso basado en roles (**RBAC**), propagación de alcance regional (`X-Region-Scope`) y exigencia estricta de **2FA TOTP** para roles privilegiados (`super_admin`).

---

## Flujo de Seguridad y Enrutamiento

```mermaid
sequenceDiagram
    participant Client as Frontend (React / TS)
    participant GW as Go API Gateway (:8080)
    participant Svc as Microservicio Interno (:8081)

    Client->>GW: GET /api/v1/reports (Bearer JWT)
    GW->>GW: Verifica firma HMAC-SHA256 y expiración
    GW->>GW: Valida RBAC + 2FA obligatorio si rol == super_admin
    GW->>Svc: Proxy HTTP + Headers (X-User-Sub, X-Region-Scope)
    Svc-->>Client: Respuesta JSON autorizada
```

## Características Clave

* **Cero Dependencias Externas:** Sin *bloat* de frameworks; usa el enrutador mejorado de Go 1.22 (`GET /health`) y `httputil.NewSingleHostReverseProxy`.
* **Prevención de Bypass MFA:** Bloquea cualquier token con rol `super_admin` que no tenga el *claim* `mfa_verified: true`.
* **Propagación de Contexto y Alcance Regional:** Inyecta cabeceras verificadas hacia los servicios internos para filtrado de datos multi-región.
* **Imagen Docker Multi-Stage Ultraligera:** Compilación estática (`CGO_ENABLED=0`) sobre `alpine:3.20` (< 15 MB) con CI automatizado en GitHub Actions (`go test -race`).

## Pruebas y Ejecución

```bash
go test -v -race ./...
docker compose up --build -d
```

---

## Autor

**Jesús A. Soto Noto** — Desarrollador de Software Full Stack  
[LinkedIn](https://www.linkedin.com/in/jesus-soto-noto) · [GitHub](https://github.com/Jesus-Soto-Noto)
