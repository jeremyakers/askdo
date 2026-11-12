package fleetproto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Join endpoints carry the same strict versioned JSON as the signed fleet
// wire, but no signature: the approved response is where the host first
// learns the gateway verification key, so nothing could verify a signature
// over it yet. The TLS channel and the host-owned join secret authenticate
// the exchange instead.

// JoinVersion is the join endpoints' wire version.
const JoinVersion = 2

// JoinTTLSeconds is the server-set lifetime of one join request.
const JoinTTLSeconds = 600

const JoinCooldownSeconds = 10

// ErrCodeJoinCapacity is an unsigned join-endpoint failure, not a general
// signed fleet failure. It distinguishes admission capacity from HTTP 503
// gateway shutdown/transport outages, which remain retryable.
const ErrCodeJoinCapacity ErrorCode = "join_capacity"

// MaxJoinHostnameBytes bounds the display-only host label.
const MaxJoinHostnameBytes = 256

// MaxJoinWireBytes bounds one join request body; responses may carry a full
// allowed-profile catalog instead.
const MaxJoinWireBytes = 4096
const MaxJoinResponseBytes = 65536

type JoinState string

const (
	JoinCommitted JoinState = "committed"
	JoinPending   JoinState = "pending"
	JoinApproved  JoinState = "approved"
	JoinDenied    JoinState = "denied"
	JoinExpired   JoinState = "expired"
)

// JoinRequest is the public initial request: only bearer/join-secret hashes
// and the host nonce commitment are sent, never the bearer or nonce itself.
type JoinRequest struct {
	Version    int    `json:"version"`
	HostID     ID     `json:"host_id"`
	BearerHash Hash   `json:"bearer_hash"`
	JoinHash   Hash   `json:"join_hash"`
	Commit     Hash   `json:"commit"`
	Hostname   string `json:"hostname"`
}

// JoinResponse reports one join's state. The approved form carries enrollment
// facts; it is not a secret and does not grant another identity. Only its
// gateway may produce it, so host code treats it as data, never authority.
type JoinResponse struct {
	Version         int       `json:"version"`
	State           JoinState `json:"state"`
	HostID          ID        `json:"host_id"`
	ExpiresAt       int64     `json:"expires_at"`
	GatewayNonce    Hash      `json:"gateway_nonce,omitempty"`
	URL             string    `json:"url,omitempty"`
	VerificationKey string    `json:"verification_key,omitempty"`
	AllowedProfiles []string  `json:"allowed_profiles,omitempty"`
	DefaultProfiles []string  `json:"default_profiles,omitempty"`
}

func ParseJoinRequest(data []byte) (JoinRequest, error) {
	var value JoinRequest
	if err := strict(data, &value, MaxJoinWireBytes); err != nil {
		return value, err
	}
	if err := validateJoinRequest(value); err != nil {
		return JoinRequest{}, err
	}
	return value, nil
}

func ParseJoinResponse(data []byte) (JoinResponse, error) {
	var value JoinResponse
	if err := strict(data, &value, MaxJoinResponseBytes); err != nil {
		return value, err
	}
	if err := validateJoinResponse(value); err != nil {
		return JoinResponse{}, err
	}
	return value, nil
}

// MarshalJoinResponse is the gateway's encoding seam: it refuses to encode a
// response that the strict parser would reject, so no unvalidated state can
// reach the wire.
func MarshalJoinResponse(value JoinResponse) ([]byte, error) {
	if err := validateJoinResponse(value); err != nil {
		return nil, err
	}
	// Empty approved selections are significant (approval-only), not absent.
	// Pointer fields preserve [] on the wire while pending/terminal states
	// omit enrollment facts entirely.
	type response JoinResponse
	wire := struct {
		response
		Allowed *[]string `json:"allowed_profiles,omitempty"`
		Default *[]string `json:"default_profiles,omitempty"`
	}{response: response(value)}
	if value.State == JoinApproved {
		wire.Allowed, wire.Default = &value.AllowedProfiles, &value.DefaultProfiles
	}
	data, err := marshalStrict(wire, MaxJoinResponseBytes)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func MarshalJoinRequest(value JoinRequest) ([]byte, error) {
	if err := validateJoinRequest(value); err != nil {
		return nil, err
	}
	return marshalStrict(value, MaxJoinWireBytes)
}

type JoinReveal struct {
	Version   int  `json:"version"`
	HostNonce Hash `json:"host_nonce"`
}

func ParseJoinReveal(data []byte) (JoinReveal, error) {
	var value JoinReveal
	if err := strict(data, &value, MaxJoinWireBytes); err != nil {
		return value, err
	}
	if value.Version != JoinVersion || !validHash(value.HostNonce) {
		return JoinReveal{}, ErrProtocol
	}
	return value, nil
}

func MarshalJoinReveal(value JoinReveal) ([]byte, error) {
	if value.Version != JoinVersion || !validHash(value.HostNonce) {
		return nil, ErrProtocol
	}
	return marshalStrict(value, MaxJoinWireBytes)
}

// JoinCommit hides the fresh host nonce until the gateway fixes its challenge.
func JoinCommit(nonce [sha256.Size]byte) Hash {
	sum := sha256.Sum256(append([]byte("askdo-join-commit\x00"), nonce[:]...))
	return Hash(hex.EncodeToString(sum[:]))
}

// marshalStrict bounds encoded unsigned join payloads.
func marshalStrict(value any, limit int) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil || len(data) > limit {
		return nil, ErrProtocol
	}
	return data, nil
}

func validateJoinRequest(v JoinRequest) error {
	if v.Version != JoinVersion || !validJoinID(v.HostID) || !validHash(v.BearerHash) || !validHash(v.JoinHash) || !validHash(v.Commit) || !validJoinHostname(v.Hostname) {
		return ErrProtocol
	}
	return nil
}

func validateJoinResponse(v JoinResponse) error {
	if v.Version != JoinVersion || !validJoinID(v.HostID) || v.ExpiresAt <= 0 {
		return ErrProtocol
	}
	if v.GatewayNonce != "" && !validHash(v.GatewayNonce) {
		return ErrProtocol
	}
	if (v.State == JoinCommitted || v.State == JoinPending || v.State == JoinApproved) && !validHash(v.GatewayNonce) {
		return ErrProtocol
	}
	switch v.State {
	case JoinCommitted, JoinPending, JoinDenied, JoinExpired:
		if v.URL != "" || v.VerificationKey != "" || v.AllowedProfiles != nil || v.DefaultProfiles != nil {
			return ErrProtocol
		}
	case JoinApproved:
		if v.URL == "" || v.VerificationKey == "" || v.AllowedProfiles == nil || v.DefaultProfiles == nil {
			return ErrProtocol
		}
		if !validJoinURL(v.URL) {
			return ErrProtocol
		}
		key, err := base64.StdEncoding.Strict().DecodeString(v.VerificationKey)
		if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != v.VerificationKey {
			return ErrProtocol
		}
		if len(v.AllowedProfiles) > MaxCatalogProfiles || len(v.DefaultProfiles) > MaxProfiles {
			return ErrProtocol
		}
		allowed := map[string]bool{}
		for _, id := range v.AllowedProfiles {
			if _, err := ParseID(id); err != nil || allowed[id] {
				return ErrProtocol
			}
			allowed[id] = true
		}
		seen := map[string]bool{}
		for _, id := range v.DefaultProfiles {
			if seen[id] || !allowed[id] {
				return ErrProtocol
			}
			seen[id] = true
		}
	default:
		return ErrProtocol
	}
	return nil
}

// validJoinID pins the join identity shape the host generates: the enrollment
// prefix plus 32 random bytes in lowercase hex.
func validJoinID(id ID) bool {
	raw := string(id)
	return strings.HasPrefix(raw, "host_") && len(raw) == len("host_")+64 && validHash(Hash(raw[len("host_"):]))
}

// ParseJoinHostID accepts exactly the identity shape the host generates for
// fleet join, so both client and server reject other spellings at their
// boundaries.
func ParseJoinHostID(s string) (ID, error) {
	if !validJoinID(ID(s)) {
		return "", ErrProtocol
	}
	return ID(s), nil
}

// validJoinHostname accepts the display-only label: bounded UTF-8 with no
// control characters at all. It is rendered escaped and never trusted.
func ValidDisplayName(s string) bool { return s != "" && validJoinHostname(s) }

func validJoinHostname(s string) bool {
	if len(s) > MaxJoinHostnameBytes || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// validJoinURL mirrors the connection URL contract: absolute HTTPS, no
// userinfo, query or fragment.
func validJoinURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") || strings.TrimSpace(raw) != raw {
		return false
	}
	if port := u.Port(); port != "" {
		return validPort(port)
	}
	return true
}

func validPort(port string) bool {
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n > 0
}

// JoinRequestCode is a short authentication string binding the request to the
// gateway's serving leaf and commit/reveal exchange. Encoding: domain
// "askdo-join-code\x00", version byte 2, NUL-terminated canonical host ID,
// bearer hash and join hash, then raw 32-byte leaf digest, commitment, host nonce
// and gateway nonce. The first three digest bytes are displayed
// as six uppercase hex digits. Approval requires comparing both displays; the
// code is not a credential and never authorizes enrollment by itself.
func JoinRequestCode(request JoinRequest, gatewayLeafSHA256 [sha256.Size]byte, hostNonce, gatewayNonce Hash) string {
	payload := []byte("askdo-join-code\x00\x02" + string(request.HostID) + "\x00" + string(request.BearerHash) + "\x00" + string(request.JoinHash) + "\x00")
	payload = append(payload, gatewayLeafSHA256[:]...)
	// Inputs are canonical 32-byte hex fields validated at the wire boundary.
	for _, hash := range []Hash{request.Commit, hostNonce, gatewayNonce} {
		raw, _ := hex.DecodeString(string(hash))
		payload = append(payload, raw...)
	}
	sum := sha256.Sum256(payload)
	return strings.ToUpper(hex.EncodeToString(sum[:3]))
}
