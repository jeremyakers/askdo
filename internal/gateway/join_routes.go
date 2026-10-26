package gateway

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
)

// joinCooldownSeconds throttles registration attempts from one source IP.
const joinCooldownSeconds = fleetproto.JoinCooldownSeconds * time.Second

// joinCooldowns is the serving process's per-IP POST throttle. Status polls
// are never throttled, and a duplicate host POST never consumes the window so
// a lost response can be retried through the duplicate path.
type joinCooldowns struct {
	mu   sync.Mutex
	next map[string]time.Time
}

func (c *joinCooldowns) allow(ip string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.next == nil {
		c.next = map[string]time.Time{}
	}
	if next, ok := c.next[ip]; ok && now.Before(next) {
		return false
	}
	for key, next := range c.next {
		if !now.Before(next) {
			delete(c.next, key)
		}
	}
	// Bound the public endpoint's throttle bookkeeping as well as its queue.
	if len(c.next) >= 1024 {
		return false
	}
	c.next[ip] = now.Add(joinCooldownSeconds)
	return true
}

func remoteIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// joinEnrollment freezes what an operator's approval will enact: the channel
// literally named default, every configured profile (selected by default too,
// zero profiles meaning approval-only), the verification key and the public
// URL. It fails before creating a request when the default channel is absent.
func (s *Server) joinEnrollment(host fleetproto.ID) (JoinEnrollment, error) {
	var channel *ChannelConfig
	for i := range s.cfg.Channels {
		if s.cfg.Channels[i].Name == "default" {
			channel = &s.cfg.Channels[i]
			break
		}
	}
	if channel == nil {
		return JoinEnrollment{}, errors.New("gateway has no channel named default")
	}
	token := s.dispatcher.aliases[channel.Bot]
	if token == "" {
		return JoinEnrollment{}, errors.New("default channel bot is unavailable")
	}
	targets := []fleetproto.Recipient{}
	for _, recipient := range channel.Recipients {
		targets = append(targets, fleetproto.Recipient{ChatID: recipient.ChatID, OperatorUserIDs: append([]int64(nil), recipient.OperatorUserIDs...)})
	}
	profiles := []string{}
	for _, profile := range s.cfg.Profiles {
		profiles = append(profiles, profile.Name)
	}
	if len(profiles) > fleetproto.MaxProfiles {
		return JoinEnrollment{}, errors.New("gateway profiles exceed the automatic join selection limit")
	}
	policy := EnrollmentPolicy{AllowedProfiles: append([]string{}, profiles...), AllowedChannels: []string{"default"}, DefaultChannel: "default", UIDChannels: map[uint32]string{}}
	if err := s.cfg.ValidateEnrollment(policy); err != nil {
		return JoinEnrollment{}, err
	}
	approved := fleetproto.JoinResponse{
		Version:         fleetproto.JoinVersion,
		State:           fleetproto.JoinApproved,
		HostID:          host,
		URL:             s.cfg.PublicURL,
		VerificationKey: base64.StdEncoding.EncodeToString(s.key.Public().(ed25519.PublicKey)),
		AllowedProfiles: append([]string{}, profiles...),
		DefaultProfiles: append([]string{}, profiles...),
	}
	return JoinEnrollment{Targets: targets, TokenHash: token, Policy: policy, Approved: approved}, nil
}

func (s *Server) handleJoinPost(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || r.URL.RawQuery != "" {
		writeFailure(w, http.StatusBadRequest, fleetproto.ErrCodeProtocol)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, fleetproto.MaxJoinWireBytes))
	if err != nil {
		writeFailure(w, http.StatusBadRequest, fleetproto.ErrCodeProtocol)
		return
	}
	request, err := fleetproto.ParseJoinRequest(data)
	if err != nil {
		writeFailure(w, http.StatusBadRequest, fleetproto.ErrCodeProtocol)
		return
	}
	// A duplicate identity is answered before the cooldown: a lost response
	// retry must learn its request already exists.
	var exists int
	if err = s.store.db.QueryRowContext(r.Context(), "SELECT EXISTS(SELECT 1 FROM gateway_pending_joins WHERE host_id=?) OR EXISTS(SELECT 1 FROM gateway_enrollments WHERE host_id=?)", string(request.HostID), string(request.HostID)).Scan(&exists); err != nil {
		writeFailure(w, http.StatusInternalServerError, fleetproto.ErrCodeTransport)
		return
	}
	if exists != 0 {
		writeFailure(w, http.StatusConflict, fleetproto.ErrCodeProtocol)
		return
	}
	if !s.joinCooldowns.allow(remoteIP(r), time.Now()) {
		w.Header().Set("Retry-After", strconv.Itoa(fleetproto.JoinCooldownSeconds))
		writeFailure(w, http.StatusTooManyRequests, fleetproto.ErrCodeTransport)
		return
	}
	enrollment, err := s.joinEnrollment(request.HostID)
	if err != nil {
		writeFailure(w, http.StatusServiceUnavailable, fleetproto.ErrCodeProtocol)
		return
	}
	response, err := s.joins.Create(r.Context(), request, enrollment)
	switch {
	case err == nil:
	case errors.Is(err, ErrJoinCap):
		writeFailure(w, http.StatusServiceUnavailable, fleetproto.ErrCodeJoinCapacity)
		return
	case errors.Is(err, ErrJoinExists):
		writeFailure(w, http.StatusConflict, fleetproto.ErrCodeProtocol)
		return
	default:
		writeFailure(w, http.StatusInternalServerError, fleetproto.ErrCodeTransport)
		return
	}
	wire, err := fleetproto.MarshalJoinResponse(response)
	if err != nil {
		writeFailure(w, http.StatusInternalServerError, fleetproto.ErrCodeProtocol)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(wire)
}

func (s *Server) handleJoinGet(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || r.URL.RawQuery != "" || len(r.Header.Values("Authorization")) != 1 {
		writeFailure(w, http.StatusUnauthorized, fleetproto.ErrCodeAuth)
		return
	}
	host, err := fleetproto.ParseJoinHostID(r.PathValue("host"))
	if err != nil {
		// A new gateway never answers 404 here: that status is reserved for
		// gateways without the join endpoints.
		writeFailure(w, http.StatusUnauthorized, fleetproto.ErrCodeAuth)
		return
	}
	auth := r.Header.Get("Authorization")
	secret, ok := cutBearer(auth)
	if !ok {
		writeFailure(w, http.StatusUnauthorized, fleetproto.ErrCodeAuth)
		return
	}
	response, err := s.joins.Status(r.Context(), string(host), secret)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			writeFailure(w, http.StatusUnauthorized, fleetproto.ErrCodeAuth)
			return
		}
		writeFailure(w, http.StatusInternalServerError, fleetproto.ErrCodeTransport)
		return
	}
	wire, err := fleetproto.MarshalJoinResponse(response)
	if err != nil {
		writeFailure(w, http.StatusInternalServerError, fleetproto.ErrCodeProtocol)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(wire)
}

func cutBearer(auth string) (string, bool) {
	const prefix = "Bearer "
	if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
		return "", false
	}
	return auth[len(prefix):], true
}
