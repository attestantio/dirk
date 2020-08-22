package golang_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/attestantio/dirk/rules"
	standardrules "github.com/attestantio/dirk/rules/standard"
	"github.com/attestantio/dirk/services/checker"
	syncmaplocker "github.com/attestantio/dirk/services/locker/syncmap"
	"github.com/attestantio/dirk/services/ruler"
	"github.com/attestantio/dirk/services/ruler/golang"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
)

func TestRunRulesSignBeaconAttestationSoak(t *testing.T) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	ctx := context.Background()

	locker, err := syncmaplocker.New(ctx)
	require.NoError(t, err)

	storagePath, err := ioutil.TempDir("", "")
	require.NoError(t, err)
	defer os.RemoveAll(storagePath)
	testRules, err := standardrules.New(ctx,
		standardrules.WithStoragePath(storagePath),
	)
	require.NoError(t, err)
	service, err := golang.New(ctx,
		golang.WithLocker(locker),
		golang.WithRules(testRules))
	require.NoError(t, err)

	// The soak test will create a number of goroutines that will all attempt to sign an attestation at the same time,
	// albeit with different data.  This should result in 1 success and the result denied.

	require.NoError(t, e2types.InitBLS())
	privKey, err := e2types.GenerateBLSPrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey().Marshal()

	// p is parallelism.
	p := 64
	runtime.GOMAXPROCS(2 * p)
	requests := make([]*rules.SignBeaconAttestationData, p)
	for i := 0; i < p; i++ {
		requests[i] = &rules.SignBeaconAttestationData{
			Domain:          []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			CommitteeIndex:  uint64(i),
			BeaconBlockRoot: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Source: &rules.Checkpoint{
				Epoch: 5,
				Root:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			},
			Target: &rules.Checkpoint{
				Epoch: 6,
				Root:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			},
		}
	}

	// Run for 256 slots.
	for curSlot := uint64(10000); curSlot < uint64(10256); curSlot++ {
		// Set up the slot-specific data.
		for i := 0; i < p; i++ {
			requests[i].Slot = curSlot
			requests[i].Source.Epoch++
			requests[i].Target.Epoch++
		}

		// Set up the counts.
		approved := uint32(0)
		denied := uint32(0)

		credentials := &checker.Credentials{
			Client: "client-test01",
		}
		// Run simultaneously (as near as we can manage).
		var wg sync.WaitGroup
		starter := make(chan interface{})
		for i := 0; i < p; i++ {
			wg.Add(1)
			go func(index int) {
				<-starter
				defer wg.Done()
				res := service.RunRules(context.Background(), credentials, ruler.ActionSignBeaconAttestation, "Test wallet", "Test account", pubKey, requests[index])
				if res == rules.APPROVED {
					atomic.AddUint32(&approved, 1)
				}
				if res == rules.DENIED {
					atomic.AddUint32(&denied, 1)
				}
			}(i)
		}
		close(starter)
		wg.Wait()
		assert.Equal(t, uint32(1), approved, fmt.Sprintf("Incorrect approvals for slot %d", curSlot))
		assert.Equal(t, uint32(p-1), denied, fmt.Sprintf("Incorrect denials for slot %d", curSlot))
	}
}

func TestRunRulesSignBeaconProposalSoak(t *testing.T) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	ctx := context.Background()

	locker, err := syncmaplocker.New(ctx)
	require.NoError(t, err)

	storagePath, err := ioutil.TempDir("", "")
	require.NoError(t, err)
	defer os.RemoveAll(storagePath)
	testRules, err := standardrules.New(ctx,
		standardrules.WithStoragePath(storagePath),
	)
	require.NoError(t, err)
	service, err := golang.New(ctx,
		golang.WithLocker(locker),
		golang.WithRules(testRules))
	require.NoError(t, err)

	// The soak test will create a number of goroutines that will all attempt to sign an attestation at the same time,
	// albeit with different data.  This should result in 1 success and the result denied.

	require.NoError(t, e2types.InitBLS())
	privKey, err := e2types.GenerateBLSPrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PublicKey().Marshal()

	// p is parallelism.
	p := 64
	runtime.GOMAXPROCS(2 * p)
	requests := make([]*rules.SignBeaconProposalData, p)
	for i := 0; i < p; i++ {
		requests[i] = &rules.SignBeaconProposalData{
			Domain:        []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			ProposerIndex: 1,
			ParentRoot:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			StateRoot:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			BodyRoot:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		}
	}

	// Run for 256 slots.
	for curSlot := uint64(10000); curSlot < uint64(10256); curSlot++ {
		// Set up the slot-specific data.
		for i := 0; i < p; i++ {
			requests[i].Slot = curSlot
		}

		// Set up the counts.
		approved := uint32(0)
		denied := uint32(0)

		credentials := &checker.Credentials{
			Client: "client-test01",
		}
		// Run simultaneously (as near as we can manage).
		var wg sync.WaitGroup
		starter := make(chan interface{})
		for i := 0; i < p; i++ {
			wg.Add(1)
			go func(index int) {
				<-starter
				defer wg.Done()
				res := service.RunRules(context.Background(), credentials, ruler.ActionSignBeaconProposal, "Test wallet", "Test account", pubKey, requests[index])
				if res == rules.APPROVED {
					atomic.AddUint32(&approved, 1)
				}
				if res == rules.DENIED {
					atomic.AddUint32(&denied, 1)
				}
			}(i)
		}
		close(starter)
		wg.Wait()
		assert.Equal(t, uint32(1), approved, fmt.Sprintf("Incorrect approvals for slot %d", curSlot))
		assert.Equal(t, uint32(p-1), denied, fmt.Sprintf("Incorrect denials for slot %d", curSlot))
	}
}
