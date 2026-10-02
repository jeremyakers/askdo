package gateway

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
)

const MaxModelOutputTokens = 16384
const codexBackendURL = "https://chatgpt.com/backend-api/codex"

// LoadSigningKey reads a root:root 0600 file containing a standard-base64
// Ed25519 seed or private key. The CLI may write either form, never raw JSON.
func LoadSigningKey(path string) (ed25519.PrivateKey, error) {
	if err := validateRootFile(path, true); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, errors.New("invalid signing key encoding")
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		key := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
		if !key.Equal(ed25519.PrivateKey(raw)) {
			return nil, errors.New("invalid signing private key")
		}
		return key, nil
	default:
		return nil, errors.New("invalid signing key size")
	}
}

func profileMetadata(p config.ModelConfig) (fleetproto.ProfileMetadata, error) {
	url := p.BaseURL
	if p.API == "openai_codex" {
		url = codexBackendURL
	}
	duration := p.RequestTimeout.Value()
	seconds := int64(duration / time.Second)
	if duration%time.Second != 0 {
		seconds++
	}
	metadata := fleetproto.ProfileMetadata{Version: 1, Kind: fleetproto.KindProfile, ProfileID: fleetproto.ID(p.Name), Upstreams: []fleetproto.Upstream{{API: fleetproto.API(p.API), BaseURL: url, Model: p.Model, DataBoundary: fleetproto.DataBoundary(p.DataBoundary), RequestTimeoutSeconds: seconds, MaxOutputTokens: MaxModelOutputTokens}}}
	var err error
	metadata.Revision, err = fleetproto.HashProfile(metadata)
	return metadata, err
}

func loadBotIDs(bots []BotConfig) (map[string]int64, error) {
	ids := map[string]int64{}
	for _, bot := range bots {
		data, err := os.ReadFile(bot.TokenFile)
		if err != nil {
			return nil, err
		}
		token := strings.TrimSpace(string(data))
		prefix, suffix, ok := strings.Cut(token, ":")
		id, err := strconv.ParseInt(prefix, 10, 64)
		if !ok || err != nil || id <= 0 || strconv.FormatInt(id, 10) != prefix || len(suffix) < 20 || len(suffix) > 128 {
			return nil, errors.New("invalid bot token identity")
		}
		for _, ch := range suffix {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-') {
				return nil, errors.New("invalid bot token format")
			}
		}
		ids[bot.Name] = id
	}
	return ids, nil
}

func (s *Server) catalog(host AuthenticatedHost, uid uint32) (fleetproto.Catalog, error) {
	channel, err := host.ChannelForUID(uid)
	if err != nil {
		return fleetproto.Catalog{}, err
	}
	result := fleetproto.Catalog{Version: 1, Kind: fleetproto.KindCatalog, HostID: fleetproto.ID(host.HostID), SubmitterUID: uid, Profiles: []fleetproto.ProfileMetadata{}, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	for _, p := range s.cfg.Profiles {
		if host.AllowsProfile(p.Name) {
			m, err := profileMetadata(p)
			if err != nil {
				return result, err
			}
			result.Profiles = append(result.Profiles, m)
		}
	}
	for _, c := range s.cfg.Channels {
		if c.Name == channel {
			r := fleetproto.RouteSnapshot{Version: 1, Kind: fleetproto.KindRoute, ChannelID: fleetproto.ID(c.Name), BotID: s.botIDs[c.Bot], TTLSeconds: c.ApprovalTTL, Recipients: []fleetproto.Recipient{}}
			for _, recipient := range c.Recipients {
				r.Recipients = append(r.Recipients, fleetproto.Recipient{ChatID: recipient.ChatID, OperatorUserIDs: append([]int64(nil), recipient.OperatorUserIDs...)})
			}
			r.Revision, err = fleetproto.HashRoute(r)
			result.Route = r
			return result, err
		}
	}
	return result, errors.New("route unavailable")
}
