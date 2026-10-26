package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetclient"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/gateway"
	"github.com/jeremyakers/askdo/internal/operator"
)

const fleetUsage = "usage: sudo askdo fleet join https://gateway[:port] [--ca-file PATH]"

type fleetConfigStore interface {
	Config() *config.Config
	SaveFleet(config.Config) error
}

type fleetFiles interface {
	write(string, []byte, operator.CredentialKind) error
	rollback() error
	commit()
}

type fleetConnectOptions struct {
	configPath, credentialsDir, bundleFile string
	force                                  bool
	join                                   bool
}

// Only the local filesystem ownership/publication boundary is substituted by
// rootless tests. Production always uses the existing root-private transaction.
var (
	loadFleetConfig       = func(path string) (fleetConfigStore, error) { return operator.LoadForFleetMutation(path) }
	fleetTrustedDirectory = operator.TrustedDirectory
	readFleetTrustFile    = operator.ReadRootTrust
	newFleetFiles         = func() fleetFiles { return new(gatewayFiles) }
	pauseFleetJoin        = func(ctx context.Context, delay time.Duration) bool {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		}
	}
)

func runFleet(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || len(args) == 1 && isHelpWord(args[0]) {
		fmt.Fprintln(stdout, fleetUsage)
		return 0
	}
	if args[0] != "join" {
		fmt.Fprintln(stderr, fleetUsage)
		return 125
	}
	if len(args) == 2 && isHelpWord(args[1]) {
		fmt.Fprintln(stdout, fleetUsage)
		return 0
	}
	if getEUID() != 0 {
		fmt.Fprintln(stderr, "fleet join requires root (run with sudo)")
		return 125
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := runFleetJoin(ctx, args[1:], defaultConfigPath, fleetSystemRunner{}, stdout, stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "fleet join:", err)
		return 1
	}
	return 0
}

func runFleetJoin(parent context.Context, args []string, path string, runner fleetSetupRunner, out, stderr io.Writer) error {
	f := gatewayFlags("fleet join")
	caPath := f.String("ca-file", "", "optional trusted gateway CA PEM file (stays on this host)")
	pos, err := parseGateway(f, args, out)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New(fleetUsage)
	}
	if err := config.ValidateHTTPSURL(pos[0]); err != nil {
		return err
	}
	// Pin and validate retained local policy before any gateway request or
	// credential write. The same pinned store protects SaveFleet from edits
	// made while the operator is considering the enrollment.
	store, err := loadFleetConfig(path)
	if err != nil {
		return err
	}
	if err = store.Config().ValidateFleetJoinPolicy(); err != nil {
		return err
	}
	var ca []byte
	if *caPath != "" {
		ca, err = readFleetTrustFile(*caPath, fleetproto.MaxPayloadBytes)
		if err != nil {
			return err
		}
	}
	hostname, err := os.Hostname()
	if err != nil {
		return errors.New("could not read local hostname")
	}
	// The identity, bearer and join secret are independently generated on the
	// host. Only hashes go in the public POST; the bearer never leaves here.
	var identity, bearer, joinSecret [32]byte
	for _, raw := range []*[32]byte{&identity, &bearer, &joinSecret} {
		if _, err = rand.Read(raw[:]); err != nil {
			return errors.New("could not generate fleet join identity")
		}
	}
	host := fleetproto.ID("host_" + hex.EncodeToString(identity[:]))
	bearerHash, joinHash := sha256.Sum256(bearer[:]), sha256.Sum256(joinSecret[:])
	request := fleetproto.JoinRequest{Version: fleetproto.JoinVersion, HostID: host, Hostname: hostname, BearerHash: fleetproto.Hash(hex.EncodeToString(bearerHash[:])), JoinHash: fleetproto.Hash(hex.EncodeToString(joinHash[:]))}
	client, err := fleetclient.NewJoinClient(pos[0], string(host), base64.RawURLEncoding.EncodeToString(joinSecret[:]), ca)
	if err != nil {
		return err
	}
	defer client.Close()
	fmt.Fprintf(out, "Fleet enrollment request code: %s\nApprove the matching fleet enrollment card in Telegram. Waiting up to 10 minutes...\n", fleetproto.JoinRequestCode(host))
	ctx, cancel := context.WithTimeout(parent, fleetproto.JoinTTLSeconds*time.Second)
	defer cancel()
	approved, err := waitFleetJoin(ctx, client, request)
	if err != nil {
		return err
	}
	bundle := gateway.EnrollmentBundle{Version: 1, URL: approved.URL, HostID: string(host), Bearer: base64.RawURLEncoding.EncodeToString(bearer[:]), VerificationKey: approved.VerificationKey, CAPEM: string(ca), AllowedProfiles: approved.AllowedProfiles, DefaultProfiles: approved.DefaultProfiles}
	if err = connectFleet(store, bundle, bundle.DefaultProfiles, len(bundle.DefaultProfiles) == 0, fleetConnectOptions{configPath: path, join: true}, out); err != nil {
		return fmt.Errorf("gateway enrollment approved but local configuration was not installed: %w", err)
	}
	// This is the normal offline host validation: real config.Load plus fleet
	// credentials/TLS trust construction, never a provider probe or AI review.
	cfg, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("enrollment succeeded but setup incomplete (offline configuration validation): %w", err)
	}
	if checkFleetHost(cfg, false, out, stderr) != 0 {
		return errors.New("enrollment succeeded but setup incomplete (offline fleet validation failed)")
	}
	if err = finishFleetSetup(parent, os.Getenv("SUDO_USER"), runner, out); err != nil {
		return fmt.Errorf("enrollment succeeded but setup incomplete: %w", err)
	}
	fmt.Fprintln(out, "Fleet enrollment and setup succeeded.\nLog out and back in once for askdo group membership, then test askdo.")
	return nil
}

func waitFleetJoin(ctx context.Context, client *fleetclient.JoinClient, request fleetproto.JoinRequest) (fleetproto.JoinResponse, error) {
	registered := false
	for {
		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		var response fleetproto.JoinResponse
		var err error
		if registered {
			response, err = client.Status(callCtx)
		} else {
			response, err = client.RequestJoin(callCtx, request)
			if errors.Is(err, fleetclient.ErrJoinDuplicate) {
				registered, err = true, nil
			}
			// A POST response may be lost after creation. Reconcile with the
			// same identity/secret before retrying the identical POST.
			if joinTransportError(err) && callCtx.Err() == nil {
				response, err = client.Status(callCtx)
				if errors.Is(err, fleetclient.ErrJoinSecret) {
					// The request was not created. Retry the same POST below.
					err = &fleetclient.Error{Code: fleetproto.ErrCodeTransport}
				}
			}
		}
		cancel()
		if ctx.Err() != nil {
			return fleetproto.JoinResponse{}, errors.New("fleet join stopped or expired; rerun fleet join to request a fresh card")
		}
		delay := time.Second
		if errors.Is(err, fleetclient.ErrJoinThrottled) {
			delay = fleetproto.JoinCooldownSeconds * time.Second
			var throttle *fleetclient.JoinThrottleError
			if errors.As(err, &throttle) {
				delay = throttle.After
			}
		} else if err != nil && !joinTransportError(err) {
			return fleetproto.JoinResponse{}, err
		}
		if err == nil && response.State != "" {
			registered = true
			if time.Now().Unix() >= response.ExpiresAt {
				return fleetproto.JoinResponse{}, errors.New("fleet enrollment request expired; rerun fleet join")
			}
			switch response.State {
			case fleetproto.JoinApproved:
				return response, nil
			case fleetproto.JoinDenied:
				return fleetproto.JoinResponse{}, errors.New("fleet enrollment denied; local configuration unchanged")
			case fleetproto.JoinExpired:
				return fleetproto.JoinResponse{}, errors.New("fleet enrollment request expired; rerun fleet join")
			case fleetproto.JoinPending:
			}
		}
		// The existing ten-minute context bounds transport and cooldown waits;
		// neither can regenerate identity or extend the enrollment lifetime.
		if !pauseFleetJoin(ctx, delay) {
			return fleetproto.JoinResponse{}, errors.New("fleet join stopped or expired; rerun fleet join")
		}
	}
}

func joinTransportError(err error) bool {
	var transport *fleetclient.Error
	return errors.As(err, &transport) && transport.Code == fleetproto.ErrCodeTransport
}
