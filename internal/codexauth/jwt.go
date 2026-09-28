package codexauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// jwtClaims decodes the payload segment of a JWT without verifying the
// signature. That is deliberate and safe here: the token arrived over
// authenticated TLS from the issuer itself (or from our own root-only 0600
// credential file), and the claims are used purely for bookkeeping — the
// account ID to send back to the issuer's own API, and the expiry that
// schedules a refresh. They are never an authorization decision inside
// askdo, so local signature verification would add no property.
func jwtClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a three-segment JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parse JWT payload: %w", err)
	}
	return claims, nil
}

// AccountID extracts the chatgpt_account_id claim from an id_token JWT. It
// checks the top-level claim first and then the nested
// "https://api.openai.com/auth" object, matching the Codex CLI's handling of
// both token shapes.
func AccountID(idToken string) (string, error) {
	claims, err := jwtClaims(idToken)
	if err != nil {
		return "", fmt.Errorf("id_token: %w", err)
	}
	if id, ok := claims["chatgpt_account_id"].(string); ok && id != "" {
		return id, nil
	}
	if auth, ok := claims["https://api.openai.com/auth"].(map[string]any); ok {
		if id, ok := auth["chatgpt_account_id"].(string); ok && id != "" {
			return id, nil
		}
	}
	return "", errors.New("id_token has no chatgpt_account_id claim")
}

// AccessTokenExpiry returns the exp claim of an access-token JWT.
func AccessTokenExpiry(accessToken string) (time.Time, error) {
	claims, err := jwtClaims(accessToken)
	if err != nil {
		return time.Time{}, fmt.Errorf("access_token: %w", err)
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}, errors.New("access_token has no numeric exp claim")
	}
	return time.Unix(int64(exp), 0).UTC(), nil
}
