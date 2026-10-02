package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"time"

	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/jobid"
	"github.com/jeremyakers/askdo/internal/telegram"
)

func ticketPath(r *http.Request) (string, error) {
	job := r.PathValue("job")
	if jobid.Validate(job) != nil {
		return "", fleetproto.ErrProtocol
	}
	return job, nil
}

func (s *Server) handleTicket(w http.ResponseWriter, r *http.Request) {
	host, err := s.AuthenticateRequest(r)
	if err != nil {
		writeAuthenticationFailure(w, err)
		return
	}
	job, err := ticketPath(r)
	if err != nil || r.URL.RawQuery != "" {
		writeFailure(w, 400, fleetproto.ErrCodeProtocol)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, fleetproto.MaxPayloadBytes))
	if err != nil {
		writeFailure(w, 400, fleetproto.ErrCodeProtocol)
		return
	}
	sub, err := fleetproto.Parse[fleetproto.TicketSubmission](data)
	if err != nil || sub.Ticket.Binding.HostID != fleetproto.ID(host.HostID) || sub.Ticket.Binding.JobID != fleetproto.ID(job) {
		writeFailure(w, 400, fleetproto.ErrCodeProtocol)
		return
	}
	old, original, err := readTicket(r.Context(), s.store.db, host.HostID, job)
	token := ""
	if err == nil {
		if !bytes.Equal(data, original) {
			writeFailure(w, 409, fleetproto.ErrCodeProtocol)
			return
		}
		token = old.TokenHash
	} else if !errors.Is(err, sql.ErrNoRows) {
		writeFailure(w, 500, fleetproto.ErrCodeTransport)
		return
	} else {
		catalog, err := s.catalog(host, sub.Ticket.Display.Identity.SubmitterUID)
		if err != nil || !reflect.DeepEqual(catalog.Route, sub.Route) {
			writeFailure(w, 409, fleetproto.ErrCodeRevision)
			return
		}
		for _, p := range sub.Profiles {
			found := false
			for _, actual := range catalog.Profiles {
				if reflect.DeepEqual(actual, p) {
					found = true
					break
				}
			}
			if !found {
				writeFailure(w, 409, fleetproto.ErrCodeRevision)
				return
			}
		}
		now := time.Now().Unix()
		if sub.Ticket.Binding.ExpiresAt <= now || sub.Ticket.Binding.ExpiresAt-now > sub.Route.TTLSeconds {
			writeFailure(w, 400, fleetproto.ErrCodeExpired)
			return
		}
		rendering, err := telegram.RenderFleet(sub.Ticket)
		if err != nil || len(rendering.Parts) != sub.Ticket.Display.SummaryParts {
			writeFailure(w, 400, fleetproto.ErrCodeProtocol)
			return
		}
		for _, channel := range s.cfg.Channels {
			if channel.Name == string(sub.Route.ChannelID) {
				token = s.dispatcher.aliases[channel.Bot]
			}
		}
		if token == "" {
			writeFailure(w, 503, fleetproto.ErrCodeDelivery)
			return
		}
	}
	ack, _, err := s.tickets.Create(r.Context(), data, token)
	if err != nil {
		status := 500
		code := fleetproto.ErrCodeTransport
		if errors.Is(err, ErrTicketConflict) {
			status = 409
			code = fleetproto.ErrCodeProtocol
		} else if errors.Is(err, ErrUnauthorized) {
			status = 401
			code = fleetproto.ErrCodeAuth
		} else if errors.Is(err, fleetproto.ErrExpired) {
			status = 400
			code = fleetproto.ErrCodeExpired
		}
		writeFailure(w, status, code)
		return
	}
	// Freeze completion is explicit lifecycle, not a synthetic model tool call.
	for attempt := uint32(1); attempt <= fleetproto.MaxProfiles; attempt++ {
		s.DropSession(sub.Ticket.Binding.HostID, sub.Ticket.Binding.JobID, attempt)
	}
	wire, err := fleetproto.Sign(s.key, ack)
	if err != nil {
		writeFailure(w, 500, fleetproto.ErrCodeProtocol)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(wire)
}

func eventQuery(r *http.Request) (uint64, time.Duration, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q) != 2 || len(q["after"]) != 1 || len(q["wait_ms"]) != 1 {
		return 0, 0, fleetproto.ErrProtocol
	}
	after, err := strconv.ParseUint(q.Get("after"), 10, 63)
	if err != nil || strconv.FormatUint(after, 10) != q.Get("after") {
		return 0, 0, fleetproto.ErrProtocol
	}
	wait, err := strconv.ParseUint(q.Get("wait_ms"), 10, 16)
	if err != nil || wait > 20000 || strconv.FormatUint(wait, 10) != q.Get("wait_ms") {
		return 0, 0, fleetproto.ErrProtocol
	}
	return after, time.Duration(wait) * time.Millisecond, nil
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	host, err := s.AuthenticateRequest(r)
	if err != nil {
		writeAuthenticationFailure(w, err)
		return
	}
	job, err := ticketPath(r)
	if err != nil {
		writeFailure(w, 400, fleetproto.ErrCodeProtocol)
		return
	}
	after, wait, err := eventQuery(r)
	if err != nil {
		writeFailure(w, 400, fleetproto.ErrCodeProtocol)
		return
	}
	if _, err = s.tickets.Get(r.Context(), host.HostID, job); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeFailure(w, 404, fleetproto.ErrCodeProtocol)
		} else {
			writeFailure(w, 500, fleetproto.ErrCodeTransport)
		}
		return
	}
	deadline := time.Now().Add(wait)
	for {
		wire, err := s.tickets.NextEvent(r.Context(), host.HostID, job, after)
		if err != nil {
			if errors.Is(err, ErrUnauthorized) {
				writeFailure(w, 401, fleetproto.ErrCodeAuth)
			} else {
				writeFailure(w, 500, fleetproto.ErrCodeTransport)
			}
			return
		}
		if len(wire) > 0 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(wire)
			return
		}
		if !time.Now().Before(deadline) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		timer := time.NewTimer(min(50*time.Millisecond, time.Until(deadline)))
		select {
		case <-r.Context().Done():
			timer.Stop()
			return
		case <-s.ctx.Done():
			timer.Stop()
			writeFailure(w, 503, fleetproto.ErrCodeTransport)
			return
		case <-timer.C:
		}
	}
}

// RevokeHost atomically disables pending tickets; the CLI can use enrollment-
// only Revoke as well, since receipt serving and winner commit read live enabled.
func (s *Server) RevokeHost(ctx context.Context, host string) error {
	return s.store.RevokeWithTickets(ctx, host, s.tickets.RevokeTickets)
}
