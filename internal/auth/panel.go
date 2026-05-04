package auth

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const devFallbackSecret = "baron-dev-panel-jwt-secret-change-me!!"

// PanelJWTSecret returns HMAC key for panel JWT (BARON_SECRET or PANEL_JWT_SECRET).
func PanelJWTSecret() string {
	s := os.Getenv("BARON_SECRET")
	if s == "" {
		s = os.Getenv("PANEL_JWT_SECRET")
	}
	if s == "" {
		if os.Getenv("GO_ENV") == "production" {
			// Render sets BARON_SECRET in render.yaml — if missing, fail loud
			return ""
		}
		return devFallbackSecret
	}
	if len(s) < 16 {
		return s + devFallbackSecret // stretch weak secrets in dev
	}
	return s
}

// SignPanelToken issues an HS256 JWT for the operator UI.
func SignPanelToken(username string, admin bool) (string, error) {
	secret := PanelJWTSecret()
	if secret == "" {
		return "", fmt.Errorf("BARON_SECRET is required in production")
	}
	claims := jwt.MapClaims{
		"sub": username,
		"adm": admin,
		"exp": time.Now().Add(12 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString([]byte(secret))
}

// ParsePanelToken validates a JWT and returns subject + admin flag.
func ParsePanelToken(tokenString string) (username string, admin bool, err error) {
	secret := PanelJWTSecret()
	if secret == "" {
		return "", false, fmt.Errorf("missing signing secret")
	}
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return "", false, err
	}
	sub, _ := claims["sub"].(string)
	var adm bool
	switch v := claims["adm"].(type) {
	case bool:
		adm = v
	case float64:
		adm = v != 0
	}
	return sub, adm, nil
}
