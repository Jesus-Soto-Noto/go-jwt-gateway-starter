package auth

import (
	"errors"
	"testing"
	"time"
)

func TestVerifyHS256AndRBAC(t *testing.T) {
	secret := []byte("unit-test-secret-key")
	now := time.Unix(1760000000, 0)

	t.Run("valid regional coordinator token", func(t *testing.T) {
		tok, err := SignHS256(Claims{
			Sub:         "user-101",
			Roles:       []string{"regional_coordinator"},
			RegionScope: "capital",
			MFAVerified: false,
			Exp:         now.Add(15 * time.Minute).Unix(),
		}, secret)
		if err != nil {
			t.Fatalf("unexpected sign error: %v", err)
		}

		claims, err := VerifyHS256(tok, secret, now)
		if err != nil {
			t.Fatalf("expected valid token, got: %v", err)
		}
		if err := claims.HasAnyRole("regional_coordinator", "analyst"); err != nil {
			t.Fatalf("expected role access, got: %v", err)
		}
		if err := claims.HasAnyRole("auditor"); !errors.Is(err, ErrForbiddenRole) {
			t.Fatalf("expected ErrForbiddenRole, got: %v", err)
		}
	})

	t.Run("super_admin without 2FA TOTP is rejected", func(t *testing.T) {
		tok, _ := SignHS256(Claims{
			Sub:         "root-1",
			Roles:       []string{"super_admin"},
			MFAVerified: false,
			Exp:         now.Add(15 * time.Minute).Unix(),
		}, secret)

		_, err := VerifyHS256(tok, secret, now)
		if !errors.Is(err, ErrMFARequired) {
			t.Fatalf("expected ErrMFARequired, got: %v", err)
		}
	})

	t.Run("super_admin with 2FA TOTP verified passes all role checks", func(t *testing.T) {
		tok, _ := SignHS256(Claims{
			Sub:         "root-1",
			Roles:       []string{"super_admin"},
			MFAVerified: true,
			Exp:         now.Add(15 * time.Minute).Unix(),
		}, secret)

		claims, err := VerifyHS256(tok, secret, now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := claims.HasAnyRole("auditor"); err != nil {
			t.Fatalf("expected super_admin full access, got: %v", err)
		}
	})

	t.Run("expired token rejected", func(t *testing.T) {
		tok, _ := SignHS256(Claims{
			Sub:   "user-102",
			Roles: []string{"analyst"},
			Exp:   now.Add(-1 * time.Minute).Unix(),
		}, secret)

		_, err := VerifyHS256(tok, secret, now)
		if !errors.Is(err, ErrExpiredToken) {
			t.Fatalf("expected ErrExpiredToken, got: %v", err)
		}
	})
}
