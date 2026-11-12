package main

import (
	"bufio"
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
	"strings"
	"syscall"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetclient"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/gateway"
	"github.com/jeremyakers/askdo/internal/operator"
)

const fleetUsage = "usage: sudo askdo-config fleet join https://gateway[:port] [--ca-file PATH] [--name NAME]\nThis terminal prints a six-character request code. Approve the Telegram card ONLY if it shows that same code.\n--ca-file supplies a trusted gateway CA; without it, confirm the matching card at the terminal's [y/N] question.\n--name sets this host's readable fleet display name (default: hostname, with a host-ID suffix for duplicates)."

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
	openFleetJoinTTY      = func() (io.ReadWriteCloser, error) { return os.OpenFile("/dev/tty", os.O_RDWR, 0) }
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
	name := f.String("name", "", "readable display name for this host (default: hostname)")
	pos, err := parseGateway(f, args, out)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New(fleetUsage)
	}
	if err := config.ValidateHTTPSURL(pos[0]); err != nil {
		return fmt.Errorf("%w; example: https://gateway.example:8443", err)
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
	if *name != "" {
		hostname = *name
	}
	if !fleetproto.ValidDisplayName(hostname) {
		return errors.New("--name must be 1 through 256 UTF-8 bytes without control characters; choose a readable host name")
	}
	// The identity, bearer and join secret are independently generated on the
	// host. Only hashes go in the public POST; the bearer never leaves here.
	var identity, bearer, joinSecret, hostNonce [32]byte
	for _, raw := range []*[32]byte{&identity, &bearer, &joinSecret, &hostNonce} {
		if _, err = rand.Read(raw[:]); err != nil {
			return errors.New("could not generate fleet join identity")
		}
	}
	host := fleetproto.ID("host_" + hex.EncodeToString(identity[:]))
	bearerHash, joinHash := sha256.Sum256(bearer[:]), sha256.Sum256(joinSecret[:])
	request := fleetproto.JoinRequest{Version: fleetproto.JoinVersion, HostID: host, Hostname: hostname, BearerHash: fleetproto.Hash(hex.EncodeToString(bearerHash[:])), JoinHash: fleetproto.Hash(hex.EncodeToString(joinHash[:])), Commit: fleetproto.JoinCommit(hostNonce)}
	hostNonceText := fleetproto.Hash(hex.EncodeToString(hostNonce[:]))
	client, err := fleetclient.NewJoinClient(pos[0], string(host), base64.RawURLEncoding.EncodeToString(joinSecret[:]), ca)
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(parent, fleetproto.JoinTTLSeconds*time.Second)
	defer cancel()
	var requestCode string
	approved, err := waitFleetJoin(ctx, client, request, hostNonceText, func(gatewayNonce fleetproto.Hash) {
		deadline, _ := ctx.Deadline()
		minutes := max(1, int((time.Until(deadline)+time.Minute-1)/time.Minute))
		unit := "minutes"
		if minutes == 1 {
			unit = "minute"
		}
		requestCode = fleetproto.JoinRequestCode(request, client.GatewayLeafHash(), hostNonceText, gatewayNonce)
		fmt.Fprintf(out, "Fleet enrollment request code: %s\nApprove the Telegram card ONLY if it shows this same code. Waiting up to %d %s...\n", requestCode, minutes, unit)
		if client.UsesProvisionalTrust() {
			fmt.Fprintln(out, "A terminal confirmation question follows gateway approval; answer yes ONLY if you compared the code and approved that Telegram card.")
		}
	})
	if err != nil {
		var connect *fleetclient.JoinConnectError
		if errors.As(err, &connect) {
			return fmt.Errorf("cannot connect to %s: %s; check the gateway address and service, then rerun fleet join", pos[0], connect.Reason)
		}
		return err
	}
	if client.UsesProvisionalTrust() {
		if err := confirmFleetJoin(requestCode); err != nil {
			return err
		}
	}
	if *caPath == "" {
		ca = client.GatewayCAPEM()
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

// A provisionally pinned peer can claim approval without ever sending a card.
// Only the operator's terminal answer authenticates that peer before any writes.
func confirmFleetJoin(code string) error {
	unconfirmed := errors.New("enrollment not confirmed; local configuration unchanged")
	tty, err := openFleetJoinTTY()
	if err != nil {
		return fmt.Errorf("%w (cannot open /dev/tty for confirmation)", unconfirmed)
	}
	defer tty.Close()
	if _, err := fmt.Fprintf(tty, "Did the Telegram card show code %s, and did you approve it? [y/N] ", code); err != nil {
		return unconfirmed
	}
	answer, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil {
		return unconfirmed
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return nil
	default:
		return unconfirmed
	}
}

// Unknown authority with an explicit CA never falls back to provisional trust.
var errJoinUntrustedGateway = errors.New("fleet join: this host does not trust the gateway's TLS certificate with --ca-file, so no enrollment request was sent; check the supplied CA, or rerun fleet join without --ca-file and confirm the certificate-bound request code")

// waitFleetJoin announces only after the reveal is accepted, never merely after
// commitment admission. Nonces and credentials survive all transport retries.
func waitFleetJoin(ctx context.Context, client *fleetclient.JoinClient, request fleetproto.JoinRequest, hostNonce fleetproto.Hash, accepted func(fleetproto.Hash)) (fleetproto.JoinResponse, error) {
	registered := false
	attempted := false // an earlier POST may have reached the gateway
	announced := false
	revealSent := false
	for {
		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		var response fleetproto.JoinResponse
		var err error
		if registered {
			response, err = client.Status(callCtx)
		} else {
			response, err = client.RequestJoin(callCtx, request)
			var connect *fleetclient.JoinConnectError
			if !attempted && errors.As(err, &connect) {
				cancel()
				return fleetproto.JoinResponse{}, err
			}
			if !errors.As(err, &connect) {
				attempted = true
			}
			if errors.Is(err, fleetclient.ErrJoinDuplicate) {
				registered = true
				response, err = client.Status(callCtx)
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
		if err == nil && response.State == fleetproto.JoinCommitted {
			registered, revealSent = true, true
			response, err = client.Reveal(callCtx, hostNonce)
			if errors.Is(err, fleetclient.ErrJoinDuplicate) || joinTransportError(err) && callCtx.Err() == nil {
				response, err = client.Status(callCtx)
			}
		}
		cancel()
		var certificate *fleetclient.JoinCertificateError
		if errors.As(err, &certificate) && certificate.UnknownAuthority {
			return fleetproto.JoinResponse{}, errJoinUntrustedGateway
		}
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
			if response.State == fleetproto.JoinPending || response.State == fleetproto.JoinApproved || response.State == fleetproto.JoinDenied {
				if !revealSent {
					return fleetproto.JoinResponse{}, &fleetclient.Error{Code: fleetproto.ErrCodeProtocol}
				}
				if !announced {
					announced = true
					accepted(response.GatewayNonce)
				}
			}
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
			case fleetproto.JoinCommitted, fleetproto.JoinPending:
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
