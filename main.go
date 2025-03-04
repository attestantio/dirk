// Copyright © 2020 - 2024 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	// #nosec G108
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"

	"github.com/attestantio/dirk/cmd"
	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/rules"
	standardrules "github.com/attestantio/dirk/rules/standard"
	standardaccountmanager "github.com/attestantio/dirk/services/accountmanager/standard"
	grpcapi "github.com/attestantio/dirk/services/api/grpc"
	"github.com/attestantio/dirk/services/checker"
	staticchecker "github.com/attestantio/dirk/services/checker/static"
	"github.com/attestantio/dirk/services/fetcher"
	memfetcher "github.com/attestantio/dirk/services/fetcher/mem"
	"github.com/attestantio/dirk/services/lister"
	standardlister "github.com/attestantio/dirk/services/lister/standard"
	"github.com/attestantio/dirk/services/locker"
	syncmaplocker "github.com/attestantio/dirk/services/locker/syncmap"
	"github.com/attestantio/dirk/services/metrics"
	nullmetrics "github.com/attestantio/dirk/services/metrics/null"
	prometheusmetrics "github.com/attestantio/dirk/services/metrics/prometheus"
	"github.com/attestantio/dirk/services/peers"
	staticpeers "github.com/attestantio/dirk/services/peers/static"
	"github.com/attestantio/dirk/services/process"
	standardprocess "github.com/attestantio/dirk/services/process/standard"
	"github.com/attestantio/dirk/services/ruler"
	goruler "github.com/attestantio/dirk/services/ruler/golang"
	"github.com/attestantio/dirk/services/sender"
	sendergrpc "github.com/attestantio/dirk/services/sender/grpc"
	"github.com/attestantio/dirk/services/signer"
	standardsigner "github.com/attestantio/dirk/services/signer/standard"
	"github.com/attestantio/dirk/services/unlocker"
	localunlocker "github.com/attestantio/dirk/services/unlocker/local"
	standardwalletmanager "github.com/attestantio/dirk/services/walletmanager/standard"
	"github.com/attestantio/dirk/util"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	zerologger "github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	majordomo "github.com/wealdtech/go-majordomo"
)

// ReleaseVersion is the release version for the code.
var ReleaseVersion = "1.2.1-rc.1"

func main() {
	ctx, cancel := context.WithCancel(context.Background())

	exit, err := fetchConfig()
	if err != nil {
		zerologger.Fatal().Err(err).Msg("Failed to fetch configuration")
	}
	if exit {
		os.Exit(0)
	}

	majordomoSvc, err := util.InitMajordomo(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialise majordomo")
	}

	exit, exitCode := runCommands(ctx, majordomoSvc)
	if exit {
		os.Exit(exitCode)
	}

	if err := initLogging(); err != nil {
		log.Fatal().Err(err).Msg("Failed to initialise logging")
	}

	if viper.GetString("server.name") == "" {
		log.Fatal().Err(err).Msg("No server name set; cannot start")
	}

	logModules()
	log.Info().Str("version", ReleaseVersion).Str("commit_hash", util.CommitHash()).Msg("Starting dirk")

	initProfiling()

	if err := initTracing(ctx, majordomoSvc); err != nil {
		log.Error().Err(err).Msg("Failed to initialise tracing")
		return
	}

	runtime.GOMAXPROCS(runtime.NumCPU() * 8)

	if err := e2types.InitBLS(); err != nil {
		log.Error().Err(err).Msg("Failed to initialise BLS library")
		return
	}

	monitor, err := startMonitor(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to start metrics service")
		return
	}
	if err := registerMetrics(ctx, monitor); err != nil {
		log.Error().Err(err).Msg("Failed to register metrics")
		return
	}
	setRelease(ctx, ReleaseVersion)
	setReady(ctx, false)

	err = startServices(ctx, majordomoSvc, monitor)
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialise services")
		return
	}
	setReady(ctx, true)

	log.Info().Msg("All services operational")

	// Wait for signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	for {
		sig := <-sigCh
		if sig == syscall.SIGINT || sig == syscall.SIGTERM || sig == os.Interrupt || sig == os.Kill {
			cancel()
			break
		}
	}

	log.Info().Msg("Stopping dirk")
	setReady(ctx, false)

	// Give services a chance to stop cleanly before we exit.
	time.Sleep(2 * time.Second)
}

// fetchConfig fetches configuration from various sources.
// If this returns true then the calling code should exit.
func fetchConfig() (bool, error) {
	pflag.String("base-dir", "", "base directory for configuration files")
	pflag.String("log-level", "info", "minimum level of messsages to log")
	pflag.String("log-file", "", "redirect log output to a file")
	pflag.String("profile-address", "", "Address on which to run Go profile server")
	pflag.String("tracing-address", "", "Address to which to send tracing data")
	pflag.Bool("show-certificates", false, "show server certificates and exit")
	pflag.Bool("show-permissions", false, "show client permissions and exit")
	pflag.Bool("version", false, "show Dirk version exit")
	pflag.Bool("export-slashing-protection", false, "export slashing protection data and exit")
	pflag.Bool("import-slashing-protection", false, "import slashing protection data and exit")
	pflag.String("genesis-validators-root", "", "genesis validators root required for slashing protection import or export")
	pflag.String("slashing-protection-file", "", "location of slashing protection file for import or export")
	pflag.Parse()
	if err := viper.BindPFlags(pflag.CommandLine); err != nil {
		return false, errors.Wrap(err, "failed to bind pflags to viper")
	}

	if viper.GetBool("version") {
		fmt.Fprintf(os.Stdout, "%s\n", ReleaseVersion)
		return true, nil
	}

	if viper.GetString("base-dir") != "" {
		// User-defined base directory.
		viper.AddConfigPath(viper.GetString("base-dir"))
		viper.SetConfigName("dirk")
	} else {
		// Home directory.
		home, err := homedir.Dir()
		if err != nil {
			return false, errors.Wrap(err, "failed to obtain home directory")
		}
		viper.AddConfigPath(home)
		viper.SetConfigName(".dirk")
	}

	// Environment settings.
	viper.SetEnvPrefix("DIRK")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()

	// Defaults.
	viper.SetDefault("logging.timestamp.format", "2006-01-02T15:04:05.000Z07:00")
	viper.SetDefault("storage-path", "storage")
	viper.SetDefault("process.generation-timeout", 70*time.Second)

	if err := viper.ReadInConfig(); err != nil {
		switch {
		case errors.As(err, &viper.ConfigFileNotFoundError{}):
			// It is allowable for Dirk to not have a configuration file, but only if
			// we have the information from elsewhere (e.g. environment variables).  Check
			// to see if we have a server name configured, as if not we aren't going to
			// get very far anyway.
			if viper.GetString("server.name") == "" {
				// Assume the underlying issue is that the configuration file is missing.
				return false, errors.Wrap(err, "could not find the configuration file")
			}
		case errors.As(err, &viper.ConfigParseError{}):
			return false, errors.Wrap(err, "could not parse the configuration file")
		default:
			return false, errors.Wrap(err, "failed to obtain configuration")
		}
	}

	return false, nil
}

// initProfiling initialises the profiling server.
func initProfiling() {
	profileAddress := viper.GetString("profile-address")
	if profileAddress != "" {
		go func() {
			log.Info().Str("profile_address", profileAddress).Msg("Starting profile server")
			server := &http.Server{
				Addr:              profileAddress,
				ReadHeaderTimeout: 5 * time.Second,
			}
			runtime.SetMutexProfileFraction(1)
			if err := server.ListenAndServe(); err != nil {
				log.Warn().Str("profile_address", profileAddress).Err(err).Msg("Failed to run profile server")
			}
		}()
	}
}

func runCommands(ctx context.Context, majordomoSvc majordomo.Service) (bool, int) {
	if viper.GetBool("show-certificates") {
		err := cmd.ShowCertificates(ctx, majordomoSvc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "show-certificates failed: %v\n", err)
			return true, 1
		}

		return true, 0
	}

	if viper.GetBool("show-permissions") {
		permissionsCfg := viper.GetStringMap("permissions")
		permissions := make(map[string][]*checker.Permissions)
		for client := range permissionsCfg {
			perms := viper.GetStringMapStringSlice(fmt.Sprintf("permissions.%s", client))
			permissions[client] = make([]*checker.Permissions, 0, len(perms))
			for path, operations := range perms {
				permissions[client] = append(permissions[client], &checker.Permissions{
					Path:       path,
					Operations: operations,
				})
			}
		}
		checker.DumpPermissions(permissions)

		return true, 0
	}

	if viper.GetBool("export-slashing-protection") {
		return true, exportSlashingProtection(ctx)
	}

	if viper.GetBool("import-slashing-protection") {
		return true, importSlashingProtection(ctx)
	}

	// No command run so no need to exit.
	return false, 0
}

func startServices(ctx context.Context, majordomoSvc majordomo.Service, monitor metrics.Service) error {
	stores, err := initStores(ctx, majordomoSvc)
	if err != nil {
		return err
	}

	unlockerSvc, err := startUnlocker(ctx, majordomoSvc, monitor)
	if err != nil {
		return errors.Wrap(err, "failed to initialise local unlocker")
	}

	checkerSvc, err := startChecker(ctx, monitor)
	if err != nil {
		return errors.Wrap(err, "failed to start permissions checker")
	}

	// Set up the fetcher.
	fetcherSvc, err := startFetcher(ctx, stores, monitor)
	if err != nil {
		return errors.Wrap(err, "failed to initialise account fetcher")
	}

	// Set up the locker.
	lockerSvc, err := startLocker(ctx, monitor)
	if err != nil {
		return errors.Wrap(err, "failed to set up locker service")
	}

	// Set up the ruler.
	rulerSvc, err := startRuler(ctx, lockerSvc, monitor)
	if err != nil {
		return errors.Wrap(err, "failed to set up ruler service")
	}

	_, err = startGrpcServer(ctx, monitor, majordomoSvc, stores, unlockerSvc, checkerSvc, fetcherSvc, rulerSvc)
	if err != nil {
		return err
	}

	return nil
}

func startMonitor(ctx context.Context) (metrics.Service, error) {
	log.Trace().Msg("Starting metrics service")
	var monitor metrics.Service
	var err error
	if viper.GetString("metrics.listen-address") == "" {
		monitor = nullmetrics.New()
	} else {
		monitor, err = prometheusmetrics.New(ctx,
			prometheusmetrics.WithLogLevel(util.LogLevel("metrics")),
			prometheusmetrics.WithAddress(viper.GetString("metrics.listen-address")),
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to start metrics service")
		}
	}

	return monitor, nil
}

func logModules() {
	buildInfo, ok := debug.ReadBuildInfo()
	if ok {
		log.Trace().Str("path", buildInfo.Path).Msg("Main package")
		for _, dep := range buildInfo.Deps {
			path := dep.Path
			if dep.Replace != nil {
				path = dep.Replace.Path
			}
			log.Trace().Str("path", path).Str("version", dep.Version).Msg("Dependency")
		}
	}
}

// initRules initialises a rules service.
func initRules(ctx context.Context) (rules.Service, error) {
	return standardrules.New(ctx,
		standardrules.WithLogLevel(util.LogLevel("rules")),
		standardrules.WithStoragePath(util.ResolvePath(viper.GetString("storage-path"))),
		standardrules.WithAdminIPs(viper.GetStringSlice("server.rules.admin-ips")),
		standardrules.WithPeriodicPruning(viper.GetBool("server.rules.periodic-pruning")),
	)
}

func initStores(ctx context.Context, majordomoSvc majordomo.Service) ([]e2wtypes.Store, error) {
	storesCfg := &core.Stores{}
	if err := viper.Unmarshal(storesCfg); err != nil {
		return nil, errors.Wrap(err, "failed to obtain stores configuration")
	}
	stores, err := core.InitStores(ctx, majordomoSvc, storesCfg.Stores)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialise stores")
	}
	if len(stores) == 0 {
		return nil, errors.New("no stores")
	}

	return stores, nil
}

func startUnlocker(ctx context.Context,
	majordomoSvc majordomo.Service,
	monitor metrics.Service,
) (
	unlocker.Service,
	error,
) {
	// Set up the unlocker.
	walletPassphrases := make([]string, 0)
	for _, key := range viper.GetStringSlice("unlocker.wallet-passphrases") {
		value, err := majordomoSvc.Fetch(ctx, key)
		if err != nil {
			return nil, errors.Wrap(err, "failed to obtain wallet passphrase for unlocker")
		}
		walletPassphrases = append(walletPassphrases, string(value))
	}
	accountPassphrases := make([]string, 0)
	for _, key := range viper.GetStringSlice("unlocker.account-passphrases") {
		value, err := majordomoSvc.Fetch(ctx, key)
		if err != nil {
			return nil, errors.Wrap(err, "failed to obtain account passphrase for unlocker")
		}
		accountPassphrases = append(accountPassphrases, string(value))
	}

	return localunlocker.New(ctx,
		localunlocker.WithLogLevel(util.LogLevel("unlocker")),
		localunlocker.WithMonitor(monitor),
		localunlocker.WithWalletPassphrases(walletPassphrases),
		localunlocker.WithAccountPassphrases(accountPassphrases),
	)
}

func startChecker(ctx context.Context, monitor metrics.Service) (checker.Service, error) {
	// Set up the checker.
	permissionsCfg := viper.GetStringMap("permissions")
	permissions := make(map[string][]*checker.Permissions)
	for client := range permissionsCfg {
		perms := viper.GetStringMapStringSlice(fmt.Sprintf("permissions.%s", client))
		permissions[client] = make([]*checker.Permissions, 0, len(perms))
		for path, operations := range perms {
			permissions[client] = append(permissions[client], &checker.Permissions{
				Path:       path,
				Operations: operations,
			})
		}
	}
	var checkerMonitor metrics.CheckerMonitor
	if monitor, isMonitor := monitor.(metrics.CheckerMonitor); isMonitor {
		checkerMonitor = monitor
	}

	return staticchecker.New(ctx,
		staticchecker.WithLogLevel(util.LogLevel("checker")),
		staticchecker.WithMonitor(checkerMonitor),
		staticchecker.WithPermissions(permissions),
	)
}

func startFetcher(ctx context.Context, stores []e2wtypes.Store, monitor metrics.Service) (fetcher.Service, error) {
	var fetcherMonitor metrics.FetcherMonitor
	if monitor, isMonitor := monitor.(metrics.FetcherMonitor); isMonitor {
		fetcherMonitor = monitor
	}

	return memfetcher.New(ctx,
		memfetcher.WithLogLevel(util.LogLevel("fetcher")),
		memfetcher.WithMonitor(fetcherMonitor),
		memfetcher.WithStores(stores),
	)
}

func startLocker(ctx context.Context, monitor metrics.Service) (locker.Service, error) {
	var lockerMonitor metrics.LockerMonitor
	if monitor, isMonitor := monitor.(metrics.LockerMonitor); isMonitor {
		lockerMonitor = monitor
	}

	return syncmaplocker.New(ctx,
		syncmaplocker.WithLogLevel(util.LogLevel("locker")),
		syncmaplocker.WithMonitor(lockerMonitor),
	)
}

func startRuler(ctx context.Context, lockerSvc locker.Service, monitor metrics.Service) (ruler.Service, error) {
	rulesSvc, err := initRules(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to set up rules")
	}
	var rulerMonitor metrics.RulerMonitor
	if monitor, isMonitor := monitor.(metrics.RulerMonitor); isMonitor {
		rulerMonitor = monitor
	}

	return goruler.New(ctx,
		goruler.WithLogLevel(util.LogLevel("ruler")),
		goruler.WithMonitor(rulerMonitor),
		goruler.WithLocker(lockerSvc),
		goruler.WithRules(rulesSvc),
	)
}

func startPeers(ctx context.Context, monitor metrics.Service) (peers.Service, error) {
	// Keys are strings.
	peersInfo := viper.GetStringMapString("peers")
	peersMap := make(map[uint64]string)
	for k, v := range peersInfo {
		id, err := strconv.ParseUint(k, 10, 64)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse peers info")
		}
		peersMap[id] = v
	}
	var peersMonitor metrics.PeersMonitor
	if monitor, isMonitor := monitor.(metrics.PeersMonitor); isMonitor {
		peersMonitor = monitor
	}

	return staticpeers.New(ctx,
		staticpeers.WithLogLevel(util.LogLevel("peers")),
		staticpeers.WithMonitor(peersMonitor),
		staticpeers.WithPeers(peersMap),
	)
}

func startLister(ctx context.Context,
	monitor metrics.Service,
	fetcherSvc fetcher.Service,
	checkerSvc checker.Service,
	rulerSvc ruler.Service,
) (
	lister.Service,
	error,
) {
	var listerMonitor metrics.ListerMonitor
	if monitor, isMonitor := monitor.(metrics.ListerMonitor); isMonitor {
		listerMonitor = monitor
	}

	return standardlister.New(ctx,
		standardlister.WithLogLevel(util.LogLevel("lister")),
		standardlister.WithMonitor(listerMonitor),
		standardlister.WithFetcher(fetcherSvc),
		standardlister.WithChecker(checkerSvc),
		standardlister.WithRuler(rulerSvc),
	)
}

func startSigner(ctx context.Context,
	monitor metrics.Service,
	fetcherSvc fetcher.Service,
	checkerSvc checker.Service,
	unlockerSvc unlocker.Service,
	rulerSvc ruler.Service,
) (
	signer.Service,
	error,
) {
	var signerMonitor metrics.SignerMonitor
	if monitor, isMonitor := monitor.(metrics.SignerMonitor); isMonitor {
		signerMonitor = monitor
	}
	signer, err := standardsigner.New(ctx,
		standardsigner.WithLogLevel(util.LogLevel("signer")),
		standardsigner.WithMonitor(signerMonitor),
		standardsigner.WithUnlocker(unlockerSvc),
		standardsigner.WithChecker(checkerSvc),
		standardsigner.WithFetcher(fetcherSvc),
		standardsigner.WithRuler(rulerSvc),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create signer service")
	}

	return signer, nil
}

func startSender(ctx context.Context,
	monitor metrics.Service,
	certPEMBlock []byte,
	keyPEMBlock []byte,
	caPEMBlock []byte,
) (
	sender.Service,
	error,
) {
	var senderMonitor metrics.SenderMonitor
	if monitor, isMonitor := monitor.(metrics.SenderMonitor); isMonitor {
		senderMonitor = monitor
	}

	senderSvc, err := sendergrpc.New(ctx,
		sendergrpc.WithLogLevel(util.LogLevel("sender")),
		sendergrpc.WithMonitor(senderMonitor),
		sendergrpc.WithName(viper.GetString("server.name")),
		sendergrpc.WithServerCert(certPEMBlock),
		sendergrpc.WithServerKey(keyPEMBlock),
		sendergrpc.WithCACert(caPEMBlock),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create sender service")
	}

	return senderSvc, nil
}

func startProcess(ctx context.Context,
	monitor metrics.Service,
	majordomoSvc majordomo.Service,
	serverID uint64,
	stores []e2wtypes.Store,
	unlockerSvc unlocker.Service,
	checkerSvc checker.Service,
	fetcherSvc fetcher.Service,
	peersSvc peers.Service,
	certPEMBlock []byte,
	keyPEMBlock []byte,
	caPEMBlock []byte,
) (
	process.Service,
	error,
) {
	sender, err := startSender(ctx, monitor, certPEMBlock, keyPEMBlock, caPEMBlock)
	if err != nil {
		return nil, err
	}

	var processMonitor metrics.ProcessMonitor
	if monitor, isMonitor := monitor.(metrics.ProcessMonitor); isMonitor {
		processMonitor = monitor
	}

	var generationPassphrase []byte
	if viper.GetString("process.generation-passphrase") != "" {
		generationPassphrase, err = majordomoSvc.Fetch(ctx, viper.GetString("process.generation-passphrase"))
		if err != nil {
			return nil, errors.Wrap(err, "failed to obtain account generation passphrase for process")
		}
	}
	if len(generationPassphrase) == 0 {
		log.Warn().Msg("No generation password supplied; distributed key generation cannot take place")
	}

	processSvc, err := standardprocess.New(ctx,
		standardprocess.WithLogLevel(util.LogLevel("process")),
		standardprocess.WithMonitor(processMonitor),
		standardprocess.WithChecker(checkerSvc),
		standardprocess.WithFetcher(fetcherSvc),
		standardprocess.WithUnlocker(unlockerSvc),
		standardprocess.WithSender(sender),
		standardprocess.WithPeers(peersSvc),
		standardprocess.WithID(serverID),
		standardprocess.WithStores(stores),
		standardprocess.WithGenerationPassphrase(generationPassphrase),
		standardprocess.WithGenerationTimeout(viper.GetDuration("process.generation-timeout")),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create process service")
	}

	return processSvc, nil
}

func startGrpcServer(ctx context.Context,
	monitor metrics.Service,
	majordomoSvc majordomo.Service,
	stores []e2wtypes.Store,
	unlockerSvc unlocker.Service,
	checkerSvc checker.Service,
	fetcherSvc fetcher.Service,
	rulerSvc ruler.Service,
) (
	*grpcapi.Service,
	error,
) {
	// Set up the lister.
	listerSvc, err := startLister(ctx, monitor, fetcherSvc, checkerSvc, rulerSvc)
	if err != nil {
		return nil, err
	}

	// Set up the signec.
	signerSvc, err := startSigner(ctx, monitor, fetcherSvc, checkerSvc, unlockerSvc, rulerSvc)
	if err != nil {
		return nil, err
	}

	peersSvc, err := startPeers(ctx, monitor)
	if err != nil {
		return nil, err
	}

	serverID, err := strconv.ParseUint(viper.GetString("server.id"), 10, 64)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain server ID")
	}

	certPEMBlock, keyPEMBlock, caPEMBlock, err := obtainCerts(ctx, majordomoSvc)
	if err != nil {
		return nil, err
	}

	processSvc, err := startProcess(ctx,
		monitor,
		majordomoSvc,
		serverID,
		stores,
		unlockerSvc,
		checkerSvc,
		fetcherSvc,
		peersSvc,
		certPEMBlock,
		keyPEMBlock,
		caPEMBlock,
	)
	if err != nil {
		return nil, err
	}

	var accountManagerMonitor metrics.AccountManagerMonitor
	if monitor, isMonitor := monitor.(metrics.AccountManagerMonitor); isMonitor {
		accountManagerMonitor = monitor
	}
	accountManager, err := standardaccountmanager.New(ctx,
		standardaccountmanager.WithLogLevel(util.LogLevel("accountmanager")),
		standardaccountmanager.WithMonitor(accountManagerMonitor),
		standardaccountmanager.WithUnlocker(unlockerSvc),
		standardaccountmanager.WithChecker(checkerSvc),
		standardaccountmanager.WithFetcher(fetcherSvc),
		standardaccountmanager.WithRuler(rulerSvc),
		standardaccountmanager.WithProcess(processSvc),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create account manager service")
	}

	var walletManagerMonitor metrics.WalletManagerMonitor
	if monitor, isMonitor := monitor.(metrics.WalletManagerMonitor); isMonitor {
		walletManagerMonitor = monitor
	}
	walletManager, err := standardwalletmanager.New(ctx,
		standardwalletmanager.WithLogLevel(util.LogLevel("walletmanager")),
		standardwalletmanager.WithMonitor(walletManagerMonitor),
		standardwalletmanager.WithUnlocker(unlockerSvc),
		standardwalletmanager.WithChecker(checkerSvc),
		standardwalletmanager.WithFetcher(fetcherSvc),
		standardwalletmanager.WithRuler(rulerSvc),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create wallet manager service")
	}

	var apiMonitor metrics.APIMonitor
	if monitor, isMonitor := monitor.(metrics.APIMonitor); isMonitor {
		apiMonitor = monitor
	}
	svc, err := grpcapi.New(ctx,
		grpcapi.WithLogLevel(util.LogLevel("api")),
		grpcapi.WithMonitor(apiMonitor),
		grpcapi.WithSigner(signerSvc),
		grpcapi.WithLister(listerSvc),
		grpcapi.WithProcess(processSvc),
		grpcapi.WithAccountManager(accountManager),
		grpcapi.WithWalletManager(walletManager),
		grpcapi.WithPeers(peersSvc),
		grpcapi.WithName(viper.GetString("server.name")),
		grpcapi.WithID(serverID),
		grpcapi.WithServerCert(certPEMBlock),
		grpcapi.WithServerKey(keyPEMBlock),
		grpcapi.WithCACert(caPEMBlock),
		grpcapi.WithListenAddress(viper.GetString("server.listen-address")),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create API service")
	}

	return svc, nil
}

func obtainCerts(ctx context.Context,
	majordomoSvc majordomo.Service,
) (
	[]byte,
	[]byte,
	[]byte,
	error,
) {
	certPEMBlock, err := majordomoSvc.Fetch(ctx, viper.GetString("certificates.server-cert"))
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, fmt.Sprintf("failed to obtain server certificate from %s", viper.GetString("certificates.server-cert")))
	}
	keyPEMBlock, err := majordomoSvc.Fetch(ctx, viper.GetString("certificates.server-key"))
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, fmt.Sprintf("failed to obtain server key from %s", viper.GetString("certificates.server-key")))
	}
	var caPEMBlock []byte
	if viper.GetString("certificates.ca-cert") != "" {
		caPEMBlock, err = majordomoSvc.Fetch(ctx, viper.GetString("certificates.ca-cert"))
		if err != nil {
			return nil, nil, nil, errors.Wrap(err, fmt.Sprintf("failed to obtain CA certificate from %s", viper.GetString("certificates.ca-cert")))
		}
	}
	return certPEMBlock, keyPEMBlock, caPEMBlock, nil
}
