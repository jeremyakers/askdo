package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetclient"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/gateway"
	"github.com/jeremyakers/askdo/internal/operator"
	"github.com/jeremyakers/askdo/internal/providers"
	"github.com/jeremyakers/askdo/internal/reviewer"
)

func gatewayLiveCheck(ctx context.Context, c *gateway.Config, out, stderr io.Writer) error {
	fmt.Fprintln(stderr, "synthetic two-turn provider fixture; may consume quota. No host files or Telegram approval messages are sent.")
	failed := false
	for _, r := range gateway.LiveCheckProfiles(ctx, *c) {
		if r.Err != nil {
			failed = true
			fmt.Fprintf(out, "profile %s: %v\n", r.Name, r.Err)
		} else {
			fmt.Fprintf(out, "profile %s: ok\n", r.Name)
		}
	}
	if failed {
		return errors.New("gateway live fixture failed")
	}
	return nil
}

func checkFleetHost(cfg *config.Config, live bool, out, stderr io.Writer) int {
	if getEUID() != 0 {
		fmt.Fprintln(stderr, "fleet config check requires root")
		return 125
	}
	// Retained bundle provenance is hard inspection protection, not an active
	// connection dependency; even a deleted source directory must not block TLS.
	connectionFiles := []string{cfg.Fleet.EnrollmentFile, cfg.Fleet.VerificationKeyFile}
	if cfg.Fleet.CAFile != "" {
		connectionFiles = append(connectionFiles, cfg.Fleet.CAFile)
	}
	for _, p := range connectionFiles {
		if err := operator.TrustedDirectory(filepath.Dir(p), false); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	client, err := fleetclient.New(*cfg.Fleet)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer client.Close()
	if !live {
		fmt.Fprintln(out, "fleet credentials and trust valid (offline)")
		return 0
	}
	fmt.Fprintln(stderr, "signed gateway catalog and synthetic two-turn tool fixture; may consume quota. No host files or Telegram messages are sent.")
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Review.TotalTimeout.Value())
	defer cancel()
	catalog, err := client.Catalogue(ctx, uint32(os.Getuid()))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	selected, err := client.Select(catalog, cfg.Review.GatewayProfiles, cfg.Review.LocalOnly)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(out, "signed fleet catalog and selected privacy boundaries: ok")
	failed := false
	for _, profile := range selected.Profiles {
		for index, upstream := range profile.Upstreams {
			var nonce [16]byte
			if _, err = rand.Read(nonce[:]); err != nil {
				fmt.Fprintln(stderr, "fixture identity generation failed")
				return 1
			}
			deadline, _ := ctx.Deadline()
			sequence := binary.BigEndian.Uint64(nonce[:8]) & ((1 << 63) - 1)
			if sequence == 0 {
				sequence = 1
			}
			jobID := fmt.Sprintf("%s_#%d", time.Now().UTC().Format("2006-01-02"), sequence)
			model := &fleetFixtureModel{client: client, selection: selected, binding: fleetproto.TurnBinding{HostID: catalog.HostID, JobID: fleetproto.ID(jobID), Attempt: 1, ProfileID: profile.ProfileID, ProfileRevision: profile.Revision, UpstreamIndex: uint32(index), Deadline: deadline.Unix()}}
			budget := time.Duration(upstream.RequestTimeoutSeconds) * time.Second
			if budget <= time.Duration((1<<63-1)/2) {
				budget *= 2
			} else {
				budget = time.Duration(1<<63 - 1)
			}
			callCtx, cancel := context.WithTimeout(ctx, budget)
			err = providers.RunLiveFixture(callCtx, model, upstream.Model, min(cfg.Review.MaxOutputTokens, upstream.MaxOutputTokens))
			cancel()
			if err != nil {
				failed = true
				fmt.Fprintf(out, "profile %s upstream %d: %v\n", profile.ProfileID, index, err)
			} else {
				fmt.Fprintf(out, "profile %s upstream %d: ok\n", profile.ProfileID, index)
			}
		}
	}
	if failed {
		return 1
	}
	return 0
}

type fleetFixtureModel struct {
	client    *fleetclient.Client
	selection fleetclient.Selection
	binding   fleetproto.TurnBinding
}

func (m *fleetFixtureModel) ChatTurn(ctx context.Context, r reviewer.ModelRequest) (reviewer.ModelResponse, error) {
	m.binding.Turn++
	result, err := m.client.ModelTurn(ctx, m.selection, fleetproto.ModelTurn{Version: 1, Kind: fleetproto.KindModelTurn, Binding: m.binding, Request: r})
	if err != nil {
		return reviewer.ModelResponse{}, err
	}
	if result.Failure != nil {
		return reviewer.ModelResponse{}, &fleetclient.Error{Code: result.Failure.Code}
	}
	if result.Response == nil {
		return reviewer.ModelResponse{}, errors.New("missing fleet fixture response")
	}
	return *result.Response, nil
}
