package main

import (
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// KeyGenResult holds the result of distributed key generation
type KeyGenResult struct {
	PublicKey    *big.Int // The shared public key (X coordinate)
	PublicKeyY   *big.Int // The shared public key (Y coordinate)
	PartyShares  []*keygen.LocalPartySaveData
	PartyIDs     tss.SortedPartyIDs
	Threshold    int
	PartyCount   int
}

// RunKeyGeneration performs distributed key generation for all parties
// Returns the shared public key and each party's share of the private key
func RunKeyGeneration(config *PartyConfig) (*KeyGenResult, error) {
	if config == nil {
		config = DefaultConfig()
	}

	fmt.Printf("Starting key generation with %d parties, threshold %d (need %d to sign)\n",
		config.PartyCount, config.Threshold, config.Threshold+1)

	// Generate party IDs
	partyIDs := GeneratePartyIDs(config.PartyCount)

	// Create channels for each party
	outChannels := make([]chan tss.Message, config.PartyCount)
	endChannels := make([]chan *keygen.LocalPartySaveData, config.PartyCount)
	errChannels := make([]chan *tss.Error, config.PartyCount)

	for i := 0; i < config.PartyCount; i++ {
		outChannels[i] = make(chan tss.Message, 100)
		endChannels[i] = make(chan *keygen.LocalPartySaveData, 1)
		errChannels[i] = make(chan *tss.Error, 1)
	}

	// Generate pre-parameters for each party (in production, pre-compute these)
	fmt.Println("Generating pre-parameters for each party (this may take a moment)...")
	preParams := make([]*keygen.LocalPreParams, config.PartyCount)
	var preParamsWg sync.WaitGroup
	preParamsWg.Add(config.PartyCount)

	for i := 0; i < config.PartyCount; i++ {
		go func(idx int) {
			defer preParamsWg.Done()
			var err error
			preParams[idx], err = keygen.GeneratePreParams(1 * time.Minute)
			if err != nil {
				fmt.Printf("Error generating pre-params for party %d: %v\n", idx, err)
			}
		}(i)
	}
	preParamsWg.Wait()

	// Verify all pre-params were generated
	for i, pp := range preParams {
		if pp == nil {
			return nil, fmt.Errorf("failed to generate pre-params for party %d", i)
		}
	}
	fmt.Println("Pre-parameters generated successfully")

	// Create parties
	parties := make([]tss.Party, config.PartyCount)
	for i := 0; i < config.PartyCount; i++ {
		params := tss.NewParameters(tss.S256(), tss.NewPeerContext(partyIDs), partyIDs[i], config.PartyCount, config.Threshold)
		party := keygen.NewLocalParty(params, outChannels[i], endChannels[i], *preParams[i])
		parties[i] = party
	}

	// Start all parties
	var startWg sync.WaitGroup
	for i := 0; i < config.PartyCount; i++ {
		startWg.Add(1)
		go func(p tss.Party, idx int) {
			defer startWg.Done()
			if err := p.Start(); err != nil {
				fmt.Printf("Error starting party %d: %v\n", idx, err)
			}
		}(parties[i], i)
	}
	startWg.Wait()

	// Run message routing and wait for completion
	results := make([]*keygen.LocalPartySaveData, config.PartyCount)
	var resultsLock sync.Mutex
	completedCount := 0
	var completedLock sync.Mutex

	// Message routing goroutine
	done := make(chan struct{})
	go func() {
		for completedCount < config.PartyCount {
			for i := 0; i < config.PartyCount; i++ {
				select {
				case msg := <-outChannels[i]:
					if msg == nil {
						continue
					}
					routeKeyGenMessage(parties, i, msg)
				case result := <-endChannels[i]:
					if result != nil {
						resultsLock.Lock()
						results[i] = result
						resultsLock.Unlock()
						completedLock.Lock()
						completedCount++
						fmt.Printf("Party %d completed key generation\n", i+1)
						completedLock.Unlock()
					}
				case err := <-errChannels[i]:
					if err != nil {
						fmt.Printf("Party %d error: %v\n", i+1, err)
					}
				default:
				}
			}
			runtime.Gosched()
		}
		close(done)
	}()

	// Wait for all parties to complete with timeout
	select {
	case <-done:
		fmt.Println("All parties completed key generation")
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("key generation timed out")
	}

	// Verify all results
	for i, r := range results {
		if r == nil {
			return nil, fmt.Errorf("party %d did not produce a result", i)
		}
	}

	// Verify all parties have the same public key
	pubKeyX := results[0].ECDSAPub.X()
	pubKeyY := results[0].ECDSAPub.Y()
	for i := 1; i < config.PartyCount; i++ {
		if results[i].ECDSAPub.X().Cmp(pubKeyX) != 0 ||
			results[i].ECDSAPub.Y().Cmp(pubKeyY) != 0 {
			return nil, fmt.Errorf("public key mismatch between parties")
		}
	}

	fmt.Printf("Key generation successful!\n")
	fmt.Printf("Shared Public Key X: %s\n", pubKeyX.Text(16)[:32]+"...")
	fmt.Printf("Shared Public Key Y: %s\n", pubKeyY.Text(16)[:32]+"...")

	return &KeyGenResult{
		PublicKey:   pubKeyX,
		PublicKeyY:  pubKeyY,
		PartyShares: results,
		PartyIDs:    partyIDs,
		Threshold:   config.Threshold,
		PartyCount:  config.PartyCount,
	}, nil
}

// routeKeyGenMessage routes a message from sender to destination parties
func routeKeyGenMessage(parties []tss.Party, senderIdx int, msg tss.Message) {
	dest := msg.GetTo()
	if dest == nil {
		// Broadcast to all parties except sender
		for j := 0; j < len(parties); j++ {
			if j == senderIdx {
				continue
			}
			go func(p tss.Party, m tss.Message) {
				if err := updatePartyWithMessage(p, m); err != nil {
					// Ignore expected routing errors
				}
			}(parties[j], msg)
		}
	} else {
		// Send to specific parties
		for _, d := range dest {
			for j := 0; j < len(parties); j++ {
				if parties[j].PartyID().Id == d.Id {
					go func(p tss.Party, m tss.Message) {
						if err := updatePartyWithMessage(p, m); err != nil {
							// Ignore expected routing errors
						}
					}(parties[j], msg)
					break
				}
			}
		}
	}
}
