package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jeremyakers/askdo/internal/config"
	"github.com/jeremyakers/askdo/internal/fleetproto"
	"github.com/jeremyakers/askdo/internal/gateway"
	"github.com/jeremyakers/askdo/internal/operator"
)

const defaultGatewayConfig = "/etc/askdo-gateway/config.json"
const gatewayUsage = "usage: askdo gateway init|hosts add|hosts list|hosts revoke HOST_ID|connect|check|serve [--config PATH]"

type gatewayStrings []string

func (v *gatewayStrings) String() string     { return "" }
func (v *gatewayStrings) Set(s string) error { *v = append(*v, s); return nil }

func runGateway(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" || args[0] == "-h" {
		fmt.Fprintln(stdout, gatewayUsage)
		return 0
	}
	helpOnly := len(args) == 2 && (args[1] == "--help" || args[1] == "-h")
	if len(args) == 3 && args[0] == "hosts" && (args[2] == "--help" || args[2] == "-h") {
		helpOnly = true
	}
	if getEUID() != 0 && !helpOnly {
		fmt.Fprintln(stderr, "gateway requires root")
		return 125
	}
	var err error
	switch args[0] {
	case "init":
		err = gatewayInit(args[1:], stdout)
	case "hosts":
		err = gatewayHosts(args[1:], stdout)
	case "connect":
		err = gatewayConnect(args[1:], stdout)
	case "check", "serve":
		err = gatewayCheckServe(args[0], args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, gatewayUsage)
		return 125
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "gateway:", err)
		return 1
	}
	return 0
}

// Parse errors deliberately do not echo argv: a mistaken secret-valued flag
// must not be reflected into terminal logs by flag's default diagnostics.
func gatewayFlags(name string) *flag.FlagSet {
	f := flag.NewFlagSet("gateway "+name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	return f
}
func parseGateway(f *flag.FlagSet, args []string, out io.Writer) ([]string, error) {
	pos, err := parseInterleaved(f, args)
	if errors.Is(err, flag.ErrHelp) {
		f.SetOutput(out)
		f.PrintDefaults()
		return nil, err
	}
	if err != nil {
		return nil, errors.New("invalid gateway arguments (use --help)")
	}
	return pos, nil
}

type gatewayFiles struct {
	files []*operator.ManagedReceipt
	done  bool
}

func (t *gatewayFiles) write(path string, data []byte, kind operator.CredentialKind) error {
	created, receipt, err := operator.WriteManagedTracked(path, data, kind, false)
	if created && receipt != nil {
		t.files = append(t.files, receipt)
	}
	return err
}
func (t *gatewayFiles) rollback() error {
	if t.done {
		return nil
	}
	var errs []error
	for i := len(t.files) - 1; i >= 0; i-- {
		errs = append(errs, t.files[i].RemoveUnchanged())
	}
	t.done = true
	return errors.Join(errs...)
}

func gatewayInit(args []string, out io.Writer) (err error) {
	f := gatewayFlags("init")
	path := f.String("config", defaultGatewayConfig, "root-private gateway configuration")
	url := f.String("url", "", "public HTTPS URL")
	listen := f.String("listen", "", "TLS listen HOST:PORT")
	cert := f.String("tls-cert", "", "operator-supplied read-only certificate file")
	key := f.String("tls-key", "", "operator-supplied root-private TLS key file")
	bot := f.String("bot-token-file", "", "existing root-private bot token file")
	chat := f.Int64("chat-id", 0, "initial recipient chat ID")
	admin := f.Int64("operator-user-id", 0, "initial operator user ID")
	db := f.String("database", "/var/lib/askdo-gateway/gateway.db", "gateway-only SQLite database")
	creds := f.String("credentials-dir", "", "defaults to config parent/credentials")
	force := f.Bool("force", false, "replace existing config; preserve existing signing identity")
	pos, e := parseGateway(f, args, out)
	if e != nil {
		return e
	}
	if len(pos) != 0 {
		return errors.New("init accepts flags only")
	}
	if *url == "" || *listen == "" || *cert == "" || *key == "" || *bot == "" || *chat == 0 || *admin <= 0 {
		return errors.New("init requires URL, listen, TLS certificate/key, bot token file, chat ID and operator user ID")
	}
	if e = config.ValidateHTTPSURL(*url); e != nil {
		return e
	}
	// Pin the currently configured identity before creating any files. Force
	// reinitialization is not a signing-key rotation or relocation operation.
	var existing *gateway.Config
	var configHash [sha256.Size]byte
	var private ed25519.PrivateKey
	if _, e = os.Lstat(*path); e == nil {
		if !*force {
			return errors.New("gateway configuration already exists (use --force)")
		}
		data, e := operator.ReadRootPrivate(*path, 1<<20)
		if e != nil {
			return e
		}
		configHash = sha256.Sum256(data)
		existing, e = gateway.DecodeConfig(data)
		if e != nil {
			return e
		}
		oldDir := filepath.Dir(existing.SigningKeyFile)
		if *creds != "" && *creds != oldDir {
			return errors.New("force init cannot relocate the existing signing identity; keep its credentials directory")
		}
		*creds = oldDir
		private, e = gateway.LoadSigningKey(existing.SigningKeyFile)
		if e != nil {
			return e
		}
		pub, e := operator.ReadRootTrust(filepath.Join(oldDir, "verification.pub"), 1<<20)
		if e != nil {
			return e
		}
		if strings.TrimSpace(string(pub)) != base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)) {
			return errors.New("existing signing identity does not match verification key")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	for _, p := range []string{*cert, *key, *bot} {
		if e = operator.TrustedDirectory(filepath.Dir(p), false); e != nil {
			return e
		}
	}
	if e = config.ValidateRootFile(*cert, false); e != nil {
		return e
	}
	if e = config.ValidateRootFile(*key, true); e != nil {
		return e
	}
	if e = config.ValidateRootFile(*bot, true); e != nil {
		return e
	}
	if _, e = tls.LoadX509KeyPair(*cert, *key); e != nil {
		return errors.New("invalid TLS certificate/key pair")
	}
	if e = operator.TrustedDirectory(filepath.Dir(*path), true); e != nil {
		return e
	}
	if *creds == "" {
		*creds = filepath.Join(filepath.Dir(*path), "credentials")
	}
	if e = operator.TrustedDirectory(*creds, true); e != nil {
		return e
	}
	if e = operator.TrustedDirectory(filepath.Dir(*db), true); e != nil {
		return e
	}
	tx := new(gatewayFiles)
	defer func() { err = errors.Join(err, tx.rollback()) }()
	signing := filepath.Join(*creds, "signing.seed")
	verification := filepath.Join(*creds, "verification.pub")
	if existing != nil {
		signing = existing.SigningKeyFile
	} else {
		_, private, e = ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		if e = tx.write(signing, []byte(base64.StdEncoding.EncodeToString(private.Seed())+"\n"), operator.CredentialGatewaySecret); e != nil {
			return e
		}
		if e = tx.write(verification, []byte(base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))+"\n"), operator.CredentialTrust); e != nil {
			return e
		}
	}
	c := gateway.Config{ConfigVersion: 1, Listen: *listen, PublicURL: *url, TLSCertFile: *cert, TLSKeyFile: *key, SigningKeyFile: signing, Database: *db, Profiles: []config.ModelConfig{}, Bots: []gateway.BotConfig{{Name: "default", TokenFile: *bot}}, Channels: []gateway.ChannelConfig{{Name: "default", Bot: "default", ApprovalTTL: 7200, Recipients: []config.TelegramRecipient{{ChatID: *chat, OperatorUserIDs: []int64{*admin}}}}}}
	if e = initializeGatewayDatabase(c, tx); e != nil {
		return e
	}
	data, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	if existing != nil {
		current, keyErr := gateway.LoadSigningKey(signing)
		if keyErr != nil {
			return keyErr
		}
		pub, pubErr := operator.ReadRootTrust(verification, 1<<20)
		if pubErr != nil {
			return pubErr
		}
		if !private.Equal(current) || strings.TrimSpace(string(pub)) != base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)) {
			return operator.ErrConfigChanged
		}
		e = operator.WriteManagedExpected(*path, append(data, '\n'), operator.CredentialGatewaySecret, configHash)
	} else {
		e = tx.write(*path, append(data, '\n'), operator.CredentialGatewaySecret)
	}
	if e != nil {
		return e
	}
	tx.done = true
	fmt.Fprintf(out, "gateway initialized: %s\nverification key: %s\n", *path, verification)
	return nil
}

// Initialize new databases privately, close SQLite, then publish the immutable
// initial image through the same pinned-inode receipt as credentials. Existing
// persistent databases are never adopted into this run's rollback ownership.
func initializeGatewayDatabase(c gateway.Config, tx *gatewayFiles) error {
	if _, err := os.Lstat(c.Database); err == nil {
		store, err := gateway.OpenEnrollmentStore(c.Database)
		if err != nil {
			return err
		}
		return errors.Join(gateway.CheckOffline(c, store), store.Close())
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir, err := os.MkdirTemp(filepath.Dir(c.Database), ".gateway-init-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	privatePath := filepath.Join(dir, "initial.db")
	store, err := gateway.OpenEnrollmentStore(privatePath)
	if err != nil {
		return err
	}
	err = errors.Join(gateway.CheckOffline(c, store), store.Close())
	if err != nil {
		return err
	}
	data, err := operator.ReadRootPrivate(privatePath, 1<<20)
	if err != nil {
		return err
	}
	return tx.write(c.Database, data, operator.CredentialGatewaySecret)
}

func loadGatewayOperator(path string) (*gateway.Config, error) {
	data, err := operator.ReadRootPrivate(path, 1<<20)
	if err != nil {
		return nil, err
	}
	c, err := gateway.DecodeConfig(data)
	if err != nil {
		return nil, err
	}
	for _, p := range append(c.CredentialPaths(), c.Database) {
		if err = operator.TrustedDirectory(filepath.Dir(p), false); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func gatewayHosts(args []string, out io.Writer) (err error) {
	if len(args) == 0 {
		return errors.New("hosts requires add, list or revoke")
	}
	sub := args[0]
	if sub != "add" && sub != "list" && sub != "revoke" {
		return errors.New("unknown hosts operation")
	}
	f := gatewayFlags("hosts " + sub)
	path := f.String("config", defaultGatewayConfig, "gateway configuration")
	var output, defaultChannel, ca *string
	var profiles, channels, routes gatewayStrings
	if sub == "add" {
		output = f.String("output", "", "new root-private enrollment bundle")
		defaultChannel = f.String("default-channel", "", "allowed default channel ID")
		ca = f.String("ca-file", "", "optional read-only CA PEM file")
		f.Var(&profiles, "profile", "allowed profile ID (repeatable; selected order)")
		f.Var(&channels, "channel", "allowed channel ID (repeatable)")
		f.Var(&routes, "uid-channel", "UID=CHANNEL route (repeatable)")
	}
	pos, e := parseGateway(f, args[1:], out)
	if e != nil {
		return e
	}
	if sub == "revoke" && len(pos) != 1 || sub != "revoke" && len(pos) != 0 {
		return errors.New("invalid hosts positional arguments")
	}
	c, e := loadGatewayOperator(*path)
	if e != nil {
		return e
	}
	store, e := gateway.OpenEnrollmentStore(c.Database)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, store.Close()) }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if sub == "list" {
		hosts, e := store.List(ctx)
		if e != nil {
			return e
		}
		for _, h := range hosts {
			if _, e = fleetproto.ParseID(h.HostID); e != nil {
				return errors.New("invalid stored enrollment identity")
			}
			fmt.Fprintf(out, "%s enabled=%t profiles=%s channels=%s default=%s\n", h.HostID, h.Enabled, strings.Join(h.AllowedProfiles, ","), strings.Join(h.AllowedChannels, ","), h.DefaultChannel)
		}
		return nil
	}
	if sub == "revoke" {
		if _, e = fleetproto.ParseID(pos[0]); e != nil {
			return errors.New("invalid host ID")
		}
		key, e := gateway.LoadSigningKey(c.SigningKeyFile)
		if e != nil {
			return e
		}
		tickets, e := gateway.NewTicketStore(store, key)
		if e != nil {
			return e
		}
		if e = store.RevokeWithTickets(ctx, pos[0], tickets.RevokeTickets); e != nil {
			return e
		}
		fmt.Fprintf(out, "revoked %s\n", pos[0])
		return nil
	}
	if *output == "" {
		return errors.New("hosts add requires --output")
	}
	policy := gateway.EnrollmentPolicy{AllowedProfiles: append([]string{}, profiles...), AllowedChannels: append([]string{}, channels...), DefaultChannel: *defaultChannel, UIDChannels: map[uint32]string{}}
	for _, route := range routes {
		uidText, ch, ok := strings.Cut(route, "=")
		uid, e := strconv.ParseUint(uidText, 10, 32)
		if !ok || e != nil || strconv.FormatUint(uid, 10) != uidText {
			return errors.New("UID route must be canonical UID=CHANNEL")
		}
		if _, ok = policy.UIDChannels[uint32(uid)]; ok {
			return errors.New("duplicate UID route")
		}
		policy.UIDChannels[uint32(uid)] = ch
	}
	if e = c.ValidateEnrollment(policy); e != nil {
		return e
	}
	if len(profiles) > fleetproto.MaxProfiles {
		return errors.New("select at most 16 default profiles")
	}
	key, e := gateway.LoadSigningKey(c.SigningKeyFile)
	if e != nil {
		return e
	}
	caPEM := ""
	if *ca != "" {
		data, e := operator.ReadRootTrust(*ca, fleetproto.MaxPayloadBytes)
		if e != nil {
			return e
		}
		caPEM = string(data)
	}
	if e = operator.TrustedDirectory(filepath.Dir(*output), false); e != nil {
		return e
	}
	host, bearer, e := store.ProvisionDisabled(ctx, policy)
	if e != nil {
		return e
	}
	exported := false
	defer func() {
		if !exported {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			e := store.Delete(cleanupCtx, host.HostID)
			err = errors.Join(err, e)
		}
	}()
	b := gateway.EnrollmentBundle{Version: 1, URL: c.PublicURL, HostID: host.HostID, Bearer: bearer, VerificationKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), CAPEM: caPEM, AllowedProfiles: policy.AllowedProfiles, DefaultProfiles: append([]string{}, profiles...)}
	if e = b.Validate(); e != nil {
		return e
	}
	data, e := json.MarshalIndent(b, "", "  ")
	if e != nil {
		return e
	}
	data = append(data, '\n')
	if _, e = gateway.DecodeEnrollmentBundle(data); e != nil {
		return e
	}
	if _, e = operator.WriteManaged(*output, data, operator.CredentialGatewaySecret, false); e != nil {
		return e
	}
	exported = true
	if e = store.Activate(ctx, host.HostID, bearer); e != nil {
		return fmt.Errorf("bundle published but enrollment activation could not be confirmed; not ready: %w", e)
	}
	fmt.Fprintf(out, "enrolled %s\nbundle: %s\n", host.HostID, *output)
	return nil
}

func gatewayConnect(args []string, out io.Writer) (err error) {
	f := gatewayFlags("connect")
	path := f.String("config", defaultConfigPath, "local host configuration")
	enrollment := f.String("enrollment", "", "root-private enrollment bundle")
	creds := f.String("credentials-dir", "", "defaults to config parent/credentials")
	force := f.Bool("force", false, "allow exact reapplication of existing enrollment files")
	approval := f.Bool("approval-only", false, "explicitly select human-only review")
	var profiles gatewayStrings
	f.Var(&profiles, "profile", "ordered selected profile ID (repeatable)")
	pos, e := parseGateway(f, args, out)
	if e != nil {
		return e
	}
	if len(pos) != 0 || *enrollment == "" {
		return errors.New("connect requires --enrollment and accepts flags only")
	}
	data, e := operator.ReadRootPrivate(*enrollment, fleetproto.MaxPayloadBytes)
	if e != nil {
		return e
	}
	bundle, e := gateway.DecodeEnrollmentBundle(data)
	if e != nil {
		return e
	}
	store, e := operator.LoadForFleetMutation(*path)
	if e != nil {
		return e
	}
	old := store.Config()
	if e = old.ValidateFleetConversionPolicy(); e != nil {
		return e
	}
	selected := append([]string{}, profiles...)
	if len(profiles) == 0 {
		selected = append([]string{}, bundle.DefaultProfiles...)
	}
	if *approval {
		if len(profiles) != 0 {
			return errors.New("--approval-only conflicts with --profile")
		}
		selected = []string{}
	}
	if e = bundle.ValidateSelection(selected); e != nil {
		return e
	}
	if len(selected) == 0 && old.Review.Mode != "approval_only" && len(old.Review.ApprovalOnlyUsers) == 0 && !*approval {
		return errors.New("empty profile selection requires explicit --approval-only")
	}
	// Retained owner bundles contain the same active bearer as the installed
	// credential. Preserve all known prior imports, not merely the current host.
	protectedBundles := []string{}
	if old.Fleet != nil {
		protectedBundles = append(protectedBundles, old.Fleet.EnrollmentBundleFiles...)
	}
	alreadyRecorded := false
	for _, path := range protectedBundles {
		if path == *enrollment {
			alreadyRecorded = true
			break
		}
	}
	if !alreadyRecorded {
		protectedBundles = append(protectedBundles, *enrollment)
	}
	if e = (config.FleetConfig{EnrollmentBundleFiles: protectedBundles}).ValidateEnrollmentBundleFiles(); e != nil {
		return e
	}
	if *creds == "" {
		*creds = filepath.Join(filepath.Dir(*path), "credentials")
	}
	if e = operator.TrustedDirectory(*creds, true); e != nil {
		return e
	}
	ttl := int64(7200)
	if old.Fleet != nil {
		ttl = old.Fleet.ApprovalTTL
	} else if old.Telegram.ApprovalTTL.Value() > 0 {
		ttl = int64(old.Telegram.ApprovalTTL.Value() / time.Second)
	}
	if old.Fleet == nil {
		for _, ch := range old.Telegram.Channels {
			if ch.Name == old.Telegram.DefaultChannel && ch.ApprovalTTL.Value() > 0 {
				ttl = int64(ch.ApprovalTTL.Value() / time.Second)
			}
		}
	}
	fleet := config.FleetConfig{URL: bundle.URL, HostID: bundle.HostID, EnrollmentFile: filepath.Join(*creds, bundle.HostID+".bearer"), VerificationKeyFile: filepath.Join(*creds, bundle.HostID+".pub"), ApprovalTTL: ttl, EnrollmentBundleFiles: protectedBundles}
	tx := new(gatewayFiles)
	defer func() { err = errors.Join(err, tx.rollback()) }()
	install := func(path string, bytes []byte, kind operator.CredentialKind) error {
		if _, e := os.Lstat(path); e == nil && *force {
			secret := kind == operator.CredentialGatewaySecret
			if e = config.ValidateRootFile(path, secret); e != nil {
				return e
			}
			info, e := os.Lstat(path)
			if e != nil {
				return e
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			want := os.FileMode(0400)
			if secret {
				want = 0600
			}
			if !ok || stat.Gid != 0 || info.Mode().Perm() != want {
				return errors.New("existing enrollment file has incompatible ownership or mode")
			}
			old, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			if string(old) != string(bytes) {
				return errors.New("existing enrollment file conflicts with bundle")
			}
			return nil
		}
		return tx.write(path, bytes, kind)
	}
	if e = install(fleet.EnrollmentFile, []byte(bundle.Bearer+"\n"), operator.CredentialGatewaySecret); e != nil {
		return e
	}
	if e = install(fleet.VerificationKeyFile, []byte(bundle.VerificationKey+"\n"), operator.CredentialTrust); e != nil {
		return e
	}
	if bundle.CAPEM != "" {
		fleet.CAFile = filepath.Join(*creds, bundle.HostID+".ca.pem")
		if e = install(fleet.CAFile, []byte(bundle.CAPEM), operator.CredentialTrust); e != nil {
			return e
		}
	}
	next := old.WithFleet(fleet, selected, *approval)
	if e = store.SaveFleet(next); e != nil {
		return e
	}
	tx.done = true
	fmt.Fprintf(out, "connected %s\nconfiguration: %s\nenrollment: %s\nverification key: %s\n", bundle.HostID, *path, fleet.EnrollmentFile, fleet.VerificationKeyFile)
	return nil
}

func gatewayCheckServe(sub string, args []string, out, stderr io.Writer) (err error) {
	f := gatewayFlags(sub)
	path := f.String("config", defaultGatewayConfig, "gateway configuration")
	var live *bool
	if sub == "check" {
		live = f.Bool("live", false, "synthetic provider tool fixture (may consume quota; no Telegram messages)")
	}
	pos, e := parseGateway(f, args, out)
	if e != nil {
		return e
	}
	if len(pos) != 0 {
		return errors.New("unexpected positional arguments")
	}
	c, e := loadGatewayOperator(*path)
	if e != nil {
		return e
	}
	store, e := gateway.OpenEnrollmentStore(c.Database)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, store.Close()) }()
	if e = gateway.CheckOffline(*c, store); e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if sub == "serve" {
		server, e := newGatewayServer(*c, store)
		if e != nil {
			return e
		}
		defer server.Close()
		return server.Serve(ctx)
	}
	fmt.Fprintln(out, "gateway configuration valid")
	if *live {
		return gatewayLiveCheck(ctx, c, out, stderr)
	}
	return nil
}
