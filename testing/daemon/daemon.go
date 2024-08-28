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

package daemon

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"

	standardrules "github.com/attestantio/dirk/rules/standard"
	standardaccountmanager "github.com/attestantio/dirk/services/accountmanager/standard"
	grpcapi "github.com/attestantio/dirk/services/api/grpc"
	"github.com/attestantio/dirk/services/checker"
	staticchecker "github.com/attestantio/dirk/services/checker/static"
	memfetcher "github.com/attestantio/dirk/services/fetcher/mem"
	standardlister "github.com/attestantio/dirk/services/lister/standard"
	syncmaplocker "github.com/attestantio/dirk/services/locker/syncmap"
	staticpeers "github.com/attestantio/dirk/services/peers/static"
	standardprocess "github.com/attestantio/dirk/services/process/standard"
	goruler "github.com/attestantio/dirk/services/ruler/golang"
	sendergrpc "github.com/attestantio/dirk/services/sender/grpc"
	standardsigner "github.com/attestantio/dirk/services/signer/standard"
	localunlocker "github.com/attestantio/dirk/services/unlocker/local"
	standardwalletmanager "github.com/attestantio/dirk/services/walletmanager/standard"
	"github.com/attestantio/dirk/testing/logger"
	"github.com/attestantio/dirk/testing/resources"
	"github.com/pkg/errors"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	distributed "github.com/wealdtech/go-eth2-wallet-distributed"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	nd "github.com/wealdtech/go-eth2-wallet-nd/v2"
	filesystem "github.com/wealdtech/go-eth2-wallet-store-filesystem"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func _byte(input string) []byte {
	res, _ := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	return res
}

// Wallet1Keys are the private keys for the accounts in 'Wallet 1'.
// These are the well-known interop keys, from index 0 to index 15.
var Wallet1Keys = [][]byte{
	_byte("0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866"),
	_byte("0x51d0b65185db6989ab0b560d6deed19c7ead0e24b9b6372cbecb1f26bdfad000"),
	_byte("0x315ed405fafe339603932eebe8dbfd650ce5dafa561f6928664c75db85f97857"),
	_byte("0x25b1166a43c109cb330af8945d364722757c65ed2bfed5444b5a2f057f82d391"),
	_byte("0x3f5615898238c4c4f906b507ee917e9ea1bb69b93f1dbd11a34d229c3b06784b"),
	_byte("0x055794614bc85ed5436c1f5cab586aab6ca84835788621091f4f3b813761e7a8"),
	_byte("0x1023c68852075965e0f7352dee3f76a84a83e7582c181c10179936c6d6348893"),
	_byte("0x3a941600dc41e5d20e818473b817a28507c23cdfdb4b659c15461ee5c71e41f5"),
	_byte("0x066e3bdc0415530e5c7fed6382d5c822c192b620203cf669903e1810a8c67d06"),
	_byte("0x2b3b88a041168a1c4cd04bdd8de7964fd35238f95442dc678514f9dadb81ec34"),
	_byte("0x2e62dbea7fe3127c3b236a92795dd633be51ee7cdfe5424882a2f355df497117"),
	_byte("0x2042dc809c130e91906c9cb0be2fec0d6afaa8f22635efc7a3c2dbf833c1851a"),
	_byte("0x15283c540041cd85c4533ee47517c8bb101c6207e9acbba2935287405a78502c"),
	_byte("0x03c85e538e1bb30235a87a3758c5571753ca1308b7dee321b74c19f78423999b"),
	_byte("0x45a577d5cab31ac5cfff381500e09655f0799f29b130e6ad61c1eec4b15bf8dd"),
	_byte("0x03cffafa1cbaa7e585eaee07a9d35ae57f6dfe19a9ea53af9c37e9f3dfac617c"),
}

// Wallet2Keys are the private keys for the accounts in 'Wallet 2'.
// These are the well-known interop keys, from index 16 to index 31.
var Wallet2Keys = [][]byte{
	// These are the well-known interop keys, starting from index 16.
	_byte("0x67496f1d63498dc62da0bf641f55125f6fc971ed1f08f7e9649e75709525fd55"),
	_byte("0x1e892380d153a5032cd54041b76de0a5f0f26dee3f189f829d5d33e720ba3934"),
	_byte("0x5a6ca99e594d26a4c8268441dcdb261f00c63e653991bf77f3e6d661dd1d7a0c"),
	_byte("0x31b5d11b313d1736237139f0c56c5503b9786ce425fbf514446e44152c794d26"),
	_byte("0x46fbedc2776c0d5db0da0d74b0a6ca45940596db7754dd87f1dbeeac396bd707"),
	_byte("0x2abf4b942eaef1bd2e92e98228890e50c408e54e0c7972c1ce67f60a5ae6fdc1"),
	_byte("0x6327b1e58c41d60dd7c3c8b9634204255707c2d12e2513c345001d8926745eea"),
	_byte("0x02a07f22259210b143686ee70a8dea2399ce18165fab780beaccdd486ddf12f4"),
	_byte("0x45113325259c7fad43feca5a07d1182e80d27dec21b069b7aee357965b07b947"),
	_byte("0x4894c61db725b9210c3acd58136797e7295d59b3a1497735fb59d5c5264bd89e"),
	_byte("0x392414fca0757c30af12c4a63afaeee64cf8a92254bd097ecd9c7696b333305a"),
	_byte("0x3e1c4fb1a25381ad757a5a2c98a522d89c796e9ad009ef00c632efbc859a9623"),
	_byte("0x2799ceccbdaf1e36679b413193a363bfe6d2d35c8cf6ff6151165707461eaed7"),
	_byte("0x27cf8e217d8481db8bc343bb6f5eb2993dc43743a2653e221df6db97be2cf004"),
	_byte("0x16782f17ec7cdbc9973e86b179ba8d779afb8e6c28cd5b9caab657fe183f64c1"),
	_byte("0x575ace3c2bf7a175b526d296e8b022357c7ceb8e799d1029d5b267d8598f449f"),
}

// New creates a Dirk daemon with pre-configured wallets and accounts.
// If path is supplied it is used to create wallets, otherwise a random filesystem path is generated.
// id is the identifier for the instance.  This should be in the range 1-5, as they are the only values
// that have certificates available.
// Because the account keys are well-known this should only be used for testing.
// Cancelling the context will kill the daemon.
//
// The specifics of what are created are:
// - ND wallet 'Wallet 1' with 16 interop keys indices 0 through 15
// - ND wallet 'Wallet 2' with 16 interop keys indices 16 through 31
// - distributed wallet 'Wallet 3' with no keys
// - full permissions for 'client-test01' to access 'Wallet 1' and 'Wallet 3'
// - full permissions for 'client-test02' to access 'Wallet 2' and 'Wallet 3'
// - full permissions for 'client-test03' to access 'Wallet 1' and 'Wallet 2'
//
// Returns the log capture for the daemon, along with the filesystem path for the wallets.
//
//nolint:maintidx
func New(ctx context.Context, path string, id uint64, port uint32, peersMap map[uint64]string) (*logger.LogCapture, string, error) {
	capture := logger.NewLogCapture()
	if err := e2types.InitBLS(); err != nil {
		return nil, "", errors.Wrap(err, "failed to initialise BLS")
	}

	// Start off creating the wallet and accounts if required.
	if path == "" {
		// #nosec G404
		path = filepath.Join(os.TempDir(), fmt.Sprintf("Dirk-%d", rand.Int31()))
	}
	store := filesystem.New(filesystem.WithLocation(path))
	encryptor := keystorev4.New()

	wallet1, err := nd.CreateWallet(ctx, "Wallet 1", store, encryptor)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to create wallet 1")
	}
	if err := wallet1.(e2wtypes.WalletLocker).Unlock(ctx, nil); err != nil {
		return nil, "", errors.Wrap(err, "failed to unlock wallet 1")
	}
	for i := range len(Wallet1Keys) {
		_, err := wallet1.(e2wtypes.WalletAccountImporter).ImportAccount(ctx,
			fmt.Sprintf("Account %d", i),
			Wallet1Keys[i],
			[]byte("pass"),
		)
		if err != nil {
			return nil, "", errors.Wrap(err, fmt.Sprintf("failed to create wallet 1 account %d", i))
		}
	}
	if err := wallet1.(e2wtypes.WalletLocker).Lock(ctx); err != nil {
		return nil, "", errors.Wrap(err, "failed to lock wallet 1")
	}

	wallet2, err := nd.CreateWallet(ctx, "Wallet 2", store, encryptor)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to create wallet 2")
	}
	if err := wallet2.(e2wtypes.WalletLocker).Unlock(ctx, nil); err != nil {
		return nil, "", errors.Wrap(err, "failed to unlock wallet 2")
	}
	for i := range len(Wallet2Keys) {
		_, err := wallet2.(e2wtypes.WalletAccountImporter).ImportAccount(ctx,
			fmt.Sprintf("Account %d", i),
			Wallet2Keys[i],
			[]byte("pass"),
		)
		if err != nil {
			return nil, "", errors.Wrap(err, fmt.Sprintf("failed to create wallet 2 account %d", i))
		}
	}
	if err := wallet2.(e2wtypes.WalletLocker).Lock(ctx); err != nil {
		return nil, "", errors.Wrap(err, "failed to lock wallet 2")
	}

	_, err = distributed.CreateWallet(ctx, "Wallet 3", store, encryptor)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to create wallet 3")
	}

	stores := []e2wtypes.Store{store}
	unlocker, err := localunlocker.New(ctx,
		localunlocker.WithWalletPassphrases([]string{"pass"}),
		localunlocker.WithAccountPassphrases([]string{"pass"}),
	)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to create local unlocker")
	}

	permissions := make(map[string][]*checker.Permissions)
	permissions["client-test01"] = []*checker.Permissions{
		{
			Path:       "Wallet 1",
			Operations: []string{"All"},
		},
		{
			Path:       "Wallet 3",
			Operations: []string{"All"},
		},
	}
	permissions["client-test02"] = []*checker.Permissions{
		{
			Path:       "Wallet 2",
			Operations: []string{"All"},
		},
		{
			Path:       "Wallet 3",
			Operations: []string{"All"},
		},
	}
	permissions["client-test03"] = []*checker.Permissions{
		{
			Path:       "Wallet 1",
			Operations: []string{"All"},
		},
		{
			Path:       "Wallet 2",
			Operations: []string{"All"},
		},
	}
	checkerSvc, err := staticchecker.New(ctx,
		staticchecker.WithPermissions(permissions),
	)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to create static checker")
	}

	fetcher, err := memfetcher.New(ctx,
		memfetcher.WithStores(stores),
		memfetcher.WithEncryptor(keystorev4.New()),
	)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to create memory fetcher")
	}

	locker, err := syncmaplocker.New(ctx)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to create syncmap locker")
	}

	storagePath := filepath.Join(path, "storage")
	rules, err := standardrules.New(ctx,
		standardrules.WithStoragePath(storagePath),
	)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to create rules")
	}
	ruler, err := goruler.New(ctx,
		goruler.WithLocker(locker),
		goruler.WithRules(rules),
	)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to create Go ruler")
	}

	lister, err := standardlister.New(ctx,
		standardlister.WithFetcher(fetcher),
		standardlister.WithChecker(checkerSvc),
		standardlister.WithRuler(ruler),
	)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to create standard lister")
	}

	signer, err := standardsigner.New(ctx,
		standardsigner.WithUnlocker(unlocker),
		standardsigner.WithChecker(checkerSvc),
		standardsigner.WithFetcher(fetcher),
		standardsigner.WithRuler(ruler),
	)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to create standard signer")
	}

	peers, err := staticpeers.New(ctx,
		staticpeers.WithPeers(peersMap),
	)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to create static peers")
	}

	sender, err := sendergrpc.New(ctx,
		sendergrpc.WithName(fmt.Sprintf("signer-test%02d", id)),
		sendergrpc.WithServerCert(resources.SignerCerts[id]),
		sendergrpc.WithServerKey(resources.SignerKeys[id]),
		sendergrpc.WithCACert(resources.CACrt),
	)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to create GRPC sender")
	}

	process, err := standardprocess.New(ctx,
		standardprocess.WithChecker(checkerSvc),
		standardprocess.WithUnlocker(unlocker),
		standardprocess.WithSender(sender),
		standardprocess.WithFetcher(fetcher),
		standardprocess.WithEncryptor(keystorev4.New()),
		standardprocess.WithPeers(peers),
		standardprocess.WithID(id),
		standardprocess.WithStores(stores),
		standardprocess.WithGenerationPassphrase([]byte("pass")),
	)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to create standard process")
	}

	accountManager, err := standardaccountmanager.New(ctx,
		standardaccountmanager.WithUnlocker(unlocker),
		standardaccountmanager.WithChecker(checkerSvc),
		standardaccountmanager.WithFetcher(fetcher),
		standardaccountmanager.WithRuler(ruler),
		standardaccountmanager.WithProcess(process),
	)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to create standard account manager")
	}

	walletManager, err := standardwalletmanager.New(ctx,
		standardwalletmanager.WithUnlocker(unlocker),
		standardwalletmanager.WithChecker(checkerSvc),
		standardwalletmanager.WithFetcher(fetcher),
		standardwalletmanager.WithRuler(ruler),
	)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to create standard wallet manager")
	}

	_, err = grpcapi.New(ctx,
		grpcapi.WithSigner(signer),
		grpcapi.WithLister(lister),
		grpcapi.WithProcess(process),
		grpcapi.WithAccountManager(accountManager),
		grpcapi.WithWalletManager(walletManager),
		grpcapi.WithPeers(peers),
		grpcapi.WithName(fmt.Sprintf("signer-test%02d", id)),
		grpcapi.WithID(id),
		grpcapi.WithServerCert(resources.SignerCerts[id]),
		grpcapi.WithServerKey(resources.SignerKeys[id]),
		grpcapi.WithCACert(resources.CACrt),
		grpcapi.WithListenAddress(fmt.Sprintf("0.0.0.0:%d", port)),
	)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to create GRPC API")
	}

	return capture, path, nil
}
