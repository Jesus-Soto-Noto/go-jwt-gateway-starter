package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var (
	ErrMalformedToken = errors.New("malformed jwt token")
	ErrInvalidSig     = errors.New("invalid token signature")
	ErrExpiredToken   = errors.New("token has expired")
	ErrForbiddenRole  = errors.New("insufficient role permissions")
	ErrMFARequired    = errors.New("multi-factor authentication (2FA TOTP) required for privileged role")
)

type Claims struct {
	Sub         string   `json:"sub"`
	Roles       []string `json:"roles"`
	RegionScope string   `json:"region_scope,omitempty"`
	MFAVerified bool     `json:"mfa_verified"`
	Exp         int64    `json:"exp"`
}

// VerifyHS256 validates an HS256 JWT token using only the Go standard library.
func VerifyHS256(tokenStr string, secret []byte, now time.Time) (*Claims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedToken
	}

	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)

	actualSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(actualSig, expectedSig) {
		return nil, ErrInvalidSig
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformedToken
	}

	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrMalformedToken
	}

	if claims.Exp <= now.Unix() {
		return nil, ErrExpiredToken
	}

	// Enforce mandatory 2FA TOTP for super_admin role (prevents MFA bypass)
	for _, r := range claims.Roles {
		if r == "super_admin" && !claims.MFAVerified {
			return nil, ErrMFARequired
		}
	}

	return &claims, nil
}

// HasAnyRole checks whether the authenticated subject holds at least one allowed role.
func (c *Claims) HasAnyRole(allowed ...string) error {
	if len(allowed) == 0 {
		return nil
	}
	roleSet := make(map[string]struct{}, len(c.Roles))
	for _, r := range c.Roles {
		roleSet[r] = struct{}{}
	}
	if _, isSuper := roleSet["super_admin"]; isSuper {
		return nil
	}
	for _, req := range allowed {
		if _, ok := roleSet[req]; ok {
			return nil
		}
	}
	return ErrForbiddenRole
}

// SignHS256 creates a signed HS256 JWT token (used in tests and local development).
func SignHS256(claims Claims, secret []byte) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	bodyBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(bodyBytes)
	signingInput := header + "." + payload

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig, nil
}
