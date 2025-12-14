package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// SignatureResult holds the result of distributed signing
type SignatureResult struct {
	R           *big.Int
	S           *big.Int
	Message     []byte
	MessageHash *big.Int
}

// RunSigning performs distributed signing with a subset of parties
// signerIndices specifies which parties participate (must be at least threshold+1)
func RunSigning(keyGenResult *KeyGenResult, message []byte, signerIndices []int) (*SignatureResult, error) {
	if len(signerIndices) <= keyGenResult.Threshold {
		return nil, fmt.Errorf("need at least %d signers, got %d",
			keyGenResult.Threshold+1, len(signerIndices))
	}

	fmt.Printf("Starting signing with %d parties for message: %s\n", len(signerIndices), string(message))

	// Hash the message
	hash := sha256.Sum256(message)
	msgHash := new(big.Int).SetBytes(hash[:])

	// Create party IDs for signers only (copy to avoid modifying original indices)
	signerPartyIDs := make([]*tss.PartyID, len(signerIndices))
	for i, idx := range signerIndices {
		orig := keyGenResult.PartyIDs[idx]
		signerPartyIDs[i] = tss.NewPartyID(orig.Id, orig.Moniker, new(big.Int).SetBytes(orig.Key))
	}
	sortedSigners := tss.SortPartyIDs(signerPartyIDs)

	// Create channels
	outChannels := make([]chan tss.Message, len(signerIndices))
	endChannels := make([]chan *common.SignatureData, len(signerIndices))
	errChannels := make([]chan *tss.Error, len(signerIndices))

	for i := 0; i < len(signerIndices); i++ {
		outChannels[i] = make(chan tss.Message, 100)
		endChannels[i] = make(chan *common.SignatureData, 1)
		errChannels[i] = make(chan *tss.Error, 1)
	}

	// Create signing parties
	parties := make([]tss.Party, len(signerIndices))
	for i, originalIdx := range signerIndices {
		params := tss.NewParameters(
			tss.S256(),
			tss.NewPeerContext(sortedSigners),
			sortedSigners[i],
			len(signerIndices),
			keyGenResult.Threshold,
		)

		// Get the saved data for this party
		savedData := keyGenResult.PartyShares[originalIdx]
		party := signing.NewLocalParty(msgHash, params, *savedData, outChannels[i], endChannels[i])
		parties[i] = party
	}

	// Start all parties
	var startWg sync.WaitGroup
	for i := 0; i < len(signerIndices); i++ {
		startWg.Add(1)
		go func(p tss.Party, idx int) {
			defer startWg.Done()
			if err := p.Start(); err != nil {
				fmt.Printf("Error starting signing party %d: %v\n", idx, err)
			}
		}(parties[i], i)
	}
	startWg.Wait()

	// Run message routing and wait for completion
	var signature *common.SignatureData
	var signatureLock sync.Mutex
	completedCount := 0
	var completedLock sync.Mutex

	done := make(chan struct{})
	go func() {
		for completedCount < len(signerIndices) {
			for i := 0; i < len(signerIndices); i++ {
				select {
				case msg := <-outChannels[i]:
					if msg == nil {
						continue
					}
					routeSigningMessage(parties, i, msg)
				case result := <-endChannels[i]:
					if result != nil {
						signatureLock.Lock()
						if signature == nil {
							signature = result
						}
						signatureLock.Unlock()
						completedLock.Lock()
						completedCount++
						fmt.Printf("Signer %d completed signing\n", signerIndices[i]+1)
						completedLock.Unlock()
					}
				case err := <-errChannels[i]:
					if err != nil {
						fmt.Printf("Signer %d error: %v\n", signerIndices[i]+1, err)
					}
				default:
				}
			}
			runtime.Gosched()
		}
		close(done)
	}()

	// Wait with timeout
	select {
	case <-done:
		fmt.Println("All signers completed signing")
	case <-time.After(2 * time.Minute):
		return nil, fmt.Errorf("signing timed out")
	}

	if signature == nil {
		return nil, fmt.Errorf("no signature produced")
	}

	r := new(big.Int).SetBytes(signature.R)
	s := new(big.Int).SetBytes(signature.S)

	fmt.Printf("Signature generated!\n")
	fmt.Printf("R: %s\n", r.Text(16)[:32]+"...")
	fmt.Printf("S: %s\n", s.Text(16)[:32]+"...")

	return &SignatureResult{
		R:           r,
		S:           s,
		Message:     message,
		MessageHash: msgHash,
	}, nil
}

// routeSigningMessage routes a message from sender to destination parties
func routeSigningMessage(parties []tss.Party, senderIdx int, msg tss.Message) {
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

// VerifySignature verifies the signature using the public key
func VerifySignature(keyGenResult *KeyGenResult, sigResult *SignatureResult) bool {
	pubKey := &ecdsa.PublicKey{
		Curve: tss.S256(),
		X:     keyGenResult.PublicKey,
		Y:     keyGenResult.PublicKeyY,
	}

	// Verify the signature
	valid := ecdsa.Verify(pubKey, sigResult.MessageHash.Bytes(), sigResult.R, sigResult.S)
	return valid
}

// SignWithNewKeyData signs a message using saved key data after resharing
func SignWithNewKeyData(partyShares []*keygen.LocalPartySaveData, partyIDs tss.SortedPartyIDs, threshold int, message []byte, signerIndices []int) (*SignatureResult, error) {
	if len(signerIndices) <= threshold {
		return nil, fmt.Errorf("need at least %d signers, got %d", threshold+1, len(signerIndices))
	}

	fmt.Printf("Starting signing with new key data for %d parties\n", len(signerIndices))

	// Hash the message
	hash := sha256.Sum256(message)
	msgHash := new(big.Int).SetBytes(hash[:])

	// Create party IDs for signers only (copy to avoid modifying original indices)
	signerPartyIDs := make([]*tss.PartyID, len(signerIndices))
	for i, idx := range signerIndices {
		orig := partyIDs[idx]
		signerPartyIDs[i] = tss.NewPartyID(orig.Id, orig.Moniker, new(big.Int).SetBytes(orig.Key))
	}
	sortedSigners := tss.SortPartyIDs(signerPartyIDs)

	// Create channels
	outChannels := make([]chan tss.Message, len(signerIndices))
	endChannels := make([]chan *common.SignatureData, len(signerIndices))
	errChannels := make([]chan *tss.Error, len(signerIndices))

	for i := 0; i < len(signerIndices); i++ {
		outChannels[i] = make(chan tss.Message, 100)
		endChannels[i] = make(chan *common.SignatureData, 1)
		errChannels[i] = make(chan *tss.Error, 1)
	}

	// Create signing parties
	parties := make([]tss.Party, len(signerIndices))
	for i, originalIdx := range signerIndices {
		params := tss.NewParameters(
			tss.S256(),
			tss.NewPeerContext(sortedSigners),
			sortedSigners[i],
			len(signerIndices),
			threshold,
		)

		savedData := partyShares[originalIdx]
		party := signing.NewLocalParty(msgHash, params, *savedData, outChannels[i], endChannels[i])
		parties[i] = party
	}

	// Start all parties
	var startWg sync.WaitGroup
	for i := 0; i < len(signerIndices); i++ {
		startWg.Add(1)
		go func(p tss.Party, idx int) {
			defer startWg.Done()
			if err := p.Start(); err != nil {
				fmt.Printf("Error starting signing party %d: %v\n", idx, err)
			}
		}(parties[i], i)
	}
	startWg.Wait()

	// Run message routing
	var signature *common.SignatureData
	var signatureLock sync.Mutex
	completedCount := 0
	var completedLock sync.Mutex

	done := make(chan struct{})
	go func() {
		for completedCount < len(signerIndices) {
			for i := 0; i < len(signerIndices); i++ {
				select {
				case msg := <-outChannels[i]:
					if msg == nil {
						continue
					}
					routeSigningMessage(parties, i, msg)
				case result := <-endChannels[i]:
					if result != nil {
						signatureLock.Lock()
						if signature == nil {
							signature = result
						}
						signatureLock.Unlock()
						completedLock.Lock()
						completedCount++
						completedLock.Unlock()
					}
				case err := <-errChannels[i]:
					if err != nil {
						fmt.Printf("Signer error: %v\n", err)
					}
				default:
				}
			}
			runtime.Gosched()
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Minute):
		return nil, fmt.Errorf("signing timed out")
	}

	if signature == nil {
		return nil, fmt.Errorf("no signature produced")
	}

	r := new(big.Int).SetBytes(signature.R)
	s := new(big.Int).SetBytes(signature.S)

	return &SignatureResult{
		R:           r,
		S:           s,
		Message:     message,
		MessageHash: msgHash,
	}, nil
}
