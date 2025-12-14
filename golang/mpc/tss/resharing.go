package main

import (
	"fmt"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// ReshareConfig holds configuration for resharing
type ReshareConfig struct {
	OldThreshold  int
	NewThreshold  int
	NewPartyCount int
}

// ReshareResult holds the result of key resharing
type ReshareResult struct {
	NewPartyShares []*keygen.LocalPartySaveData
	NewPartyIDs    tss.SortedPartyIDs
	NewThreshold   int
	NewPartyCount  int
}

// RunResharing performs key resharing from old parties to new parties
// This allows changing the threshold, adding/removing parties, or refreshing shares
func RunResharing(keyGenResult *KeyGenResult, config *ReshareConfig) (*ReshareResult, error) {
	if config == nil {
		config = &ReshareConfig{
			OldThreshold:  keyGenResult.Threshold,
			NewThreshold:  keyGenResult.Threshold,
			NewPartyCount: keyGenResult.PartyCount,
		}
	}

	fmt.Printf("Starting resharing: %d parties (threshold %d) -> %d parties (threshold %d)\n",
		keyGenResult.PartyCount, keyGenResult.Threshold,
		config.NewPartyCount, config.NewThreshold)

	oldPartyCount := keyGenResult.PartyCount

	// Generate new party IDs with DIFFERENT key values from old parties
	newPartyIDs := make([]*tss.PartyID, config.NewPartyCount)
	for i := 0; i < config.NewPartyCount; i++ {
		keyVal := new(big.Int).SetInt64(int64(100 + i + 1))
		newPartyIDs[i] = tss.NewPartyID(
			fmt.Sprintf("new-party-%d", i+1),
			fmt.Sprintf("New Party %d", i+1),
			keyVal,
		)
	}
	sortedNewPartyIDs := tss.SortPartyIDs(newPartyIDs)

	// Create peer contexts
	oldP2PCtx := tss.NewPeerContext(keyGenResult.PartyIDs)
	newP2PCtx := tss.NewPeerContext(sortedNewPartyIDs)

	// Shared channels for all parties
	errCh := make(chan *tss.Error, oldPartyCount+config.NewPartyCount)
	outCh := make(chan tss.Message, oldPartyCount+config.NewPartyCount)
	endCh := make(chan *keygen.LocalPartySaveData, oldPartyCount+config.NewPartyCount)

	// Create old committee parties
	oldCommittee := make([]*resharing.LocalParty, 0, oldPartyCount)
	for i := 0; i < oldPartyCount; i++ {
		params := tss.NewReSharingParameters(
			tss.S256(),
			oldP2PCtx,
			newP2PCtx,
			keyGenResult.PartyIDs[i],
			oldPartyCount,
			keyGenResult.Threshold,
			config.NewPartyCount,
			config.NewThreshold,
		)
		P := resharing.NewLocalParty(params, *keyGenResult.PartyShares[i], outCh, endCh).(*resharing.LocalParty)
		oldCommittee = append(oldCommittee, P)
	}

	// Create new committee parties
	newCommittee := make([]*resharing.LocalParty, 0, config.NewPartyCount)

	// Generate pre-params for new parties (reuse from keygen for speed)
	fmt.Println("Generating pre-parameters for new parties...")
	newPreParams := make([]*keygen.LocalPreParams, config.NewPartyCount)
	for i := 0; i < config.NewPartyCount; i++ {
		var err error
		newPreParams[i], err = keygen.GeneratePreParams(1 * time.Minute)
		if err != nil {
			return nil, fmt.Errorf("failed to generate pre-params for new party %d: %v", i, err)
		}
	}
	fmt.Println("Pre-parameters generated successfully")

	for i := 0; i < config.NewPartyCount; i++ {
		params := tss.NewReSharingParameters(
			tss.S256(),
			oldP2PCtx,
			newP2PCtx,
			sortedNewPartyIDs[i],
			oldPartyCount,
			keyGenResult.Threshold,
			config.NewPartyCount,
			config.NewThreshold,
		)
		// Skip proofs for faster execution (not recommended for production)
		params.SetNoProofMod()
		params.SetNoProofFac()

		save := keygen.NewLocalPartySaveData(config.NewPartyCount)
		save.LocalPreParams = *newPreParams[i]
		P := resharing.NewLocalParty(params, save, outCh, endCh).(*resharing.LocalParty)
		newCommittee = append(newCommittee, P)
	}

	// Start new parties first (they wait for messages)
	for _, P := range newCommittee {
		go func(P *resharing.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	// Start old parties (they send messages)
	for _, P := range oldCommittee {
		go func(P *resharing.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	// Track completion
	newKeys := make([]keygen.LocalPartySaveData, config.NewPartyCount)
	var reSharingEnded int32
	totalParties := int32(oldPartyCount + config.NewPartyCount)

	// Set up timeout
	timeout := time.After(5 * time.Minute)

	// Message routing loop
	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("resharing timed out")

		case err := <-errCh:
			if err != nil {
				return nil, fmt.Errorf("resharing error: %v", err)
			}

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				return nil, fmt.Errorf("unexpected nil destination in resharing message")
			}

			// Route to old committee if needed
			if msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
				for _, destP := range dest {
					if destP.Index < len(oldCommittee) {
						go sharedPartyUpdater(oldCommittee[destP.Index], msg, errCh)
					}
				}
			}

			// Route to new committee if needed
			if !msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
				for _, destP := range dest {
					if destP.Index < len(newCommittee) {
						go sharedPartyUpdater(newCommittee[destP.Index], msg, errCh)
					}
				}
			}

		case save := <-endCh:
			// Old committee members that aren't receiving a share have Xi zeroed
			if save.Xi != nil {
				index, err := save.OriginalIndex()
				if err != nil {
					return nil, fmt.Errorf("error getting party index: %v", err)
				}
				newKeys[index] = *save
				fmt.Printf("New party %d received new share\n", index+1)
			} else {
				// Old party completed
			}

			atomic.AddInt32(&reSharingEnded, 1)
			if atomic.LoadInt32(&reSharingEnded) == totalParties {
				fmt.Println("Resharing completed successfully")
				goto done
			}
		}
	}

done:
	// Convert to pointer slice and verify public keys
	result := make([]*keygen.LocalPartySaveData, config.NewPartyCount)
	for i := range newKeys {
		result[i] = &newKeys[i]
		if result[i].ECDSAPub.X().Cmp(keyGenResult.PublicKey) != 0 ||
			result[i].ECDSAPub.Y().Cmp(keyGenResult.PublicKeyY) != 0 {
			return nil, fmt.Errorf("public key mismatch for new party %d", i)
		}
	}

	fmt.Printf("Resharing successful! Public key preserved.\n")
	fmt.Printf("New threshold: %d (need %d to sign)\n", config.NewThreshold, config.NewThreshold+1)

	return &ReshareResult{
		NewPartyShares: result,
		NewPartyIDs:    sortedNewPartyIDs,
		NewThreshold:   config.NewThreshold,
		NewPartyCount:  config.NewPartyCount,
	}, nil
}

// sharedPartyUpdater updates a party with a message (based on tss-lib test utility)
func sharedPartyUpdater(party tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
	// Do not send a message from this party back to itself
	if party.PartyID() == msg.GetFrom() {
		return
	}

	bz, _, err := msg.WireBytes()
	if err != nil {
		errCh <- party.WrapError(err)
		return
	}

	pMsg, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
	if err != nil {
		errCh <- party.WrapError(err)
		return
	}

	if _, err := party.Update(pMsg); err != nil {
		errCh <- err
	}
}

// RefreshShares performs a simple share refresh without changing the committee
// This is a special case of resharing where old and new parties are the same
func RefreshShares(keyGenResult *KeyGenResult) (*ReshareResult, error) {
	fmt.Println("Refreshing shares (same parties, same threshold, new shares)")

	return RunResharing(keyGenResult, &ReshareConfig{
		OldThreshold:  keyGenResult.Threshold,
		NewThreshold:  keyGenResult.Threshold,
		NewPartyCount: keyGenResult.PartyCount,
	})
}
