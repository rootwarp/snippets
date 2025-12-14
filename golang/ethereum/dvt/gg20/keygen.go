package gg20

import (
	"fmt"
	"math/big"
)

// Party represents a participant in the MPC protocol
type Party struct {
	Index        int           // Party index (1-indexed for Shamir)
	SecretShare  *big.Int      // x_i: party's share of the secret key
	PublicKey    *Point        // Y = g^x: the joint public key
	Commitments  []*Point      // Feldman VSS commitments from this party
	ReceivedShares map[int]*big.Int // Shares received from other parties
}

// KeyGenContext holds the state for distributed key generation
type KeyGenContext struct {
	Threshold    int                // t: minimum parties needed
	TotalParties int                // n: total number of parties
	Parties      map[int]*Party     // All parties
	PublicKey    *Point             // Joint public key
}

// KeyGenRound1Output represents output from round 1 of key generation
type KeyGenRound1Output struct {
	PartyIndex   int
	Commitments  []*Point           // Feldman VSS commitments
	Shares       map[int]*big.Int   // Shares for each party (encrypted in practice)
}

// NewKeyGenContext creates a new key generation context
func NewKeyGenContext(threshold, totalParties int) (*KeyGenContext, error) {
	if threshold < 1 {
		return nil, fmt.Errorf("threshold must be at least 1")
	}
	if totalParties < threshold {
		return nil, fmt.Errorf("total parties must be >= threshold")
	}

	return &KeyGenContext{
		Threshold:    threshold,
		TotalParties: totalParties,
		Parties:      make(map[int]*Party),
	}, nil
}

// KeyGenRound1 performs round 1 of distributed key generation for a party
// Each party:
// 1. Generates a random polynomial f_i(x) of degree t-1
// 2. Creates Feldman VSS commitments: A_{i,j} = g^{a_{i,j}}
// 3. Computes shares for all parties: s_{i,j} = f_i(j)
func KeyGenRound1(partyIndex, threshold, totalParties int) (*KeyGenRound1Output, *Polynomial, error) {
	// Generate random secret share contribution
	secretContribution, err := RandomScalar()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate secret: %w", err)
	}

	// Create random polynomial with secret as constant term
	poly, err := RandomPolynomial(threshold-1, secretContribution)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate polynomial: %w", err)
	}

	// Generate Feldman VSS commitments
	commitments := poly.CommitmentPolynomial()

	// Compute shares for all parties
	shares := make(map[int]*big.Int)
	for j := 1; j <= totalParties; j++ {
		shares[j] = poly.Eval(big.NewInt(int64(j)))
	}

	output := &KeyGenRound1Output{
		PartyIndex:  partyIndex,
		Commitments: commitments,
		Shares:      shares,
	}

	return output, poly, nil
}

// KeyGenRound2 performs round 2 of distributed key generation
// Each party:
// 1. Verifies received shares against commitments
// 2. Computes their final secret share as sum of all received shares
// 3. Computes the joint public key
func KeyGenRound2(partyIndex int, receivedOutputs []*KeyGenRound1Output) (*Party, error) {
	if len(receivedOutputs) == 0 {
		return nil, fmt.Errorf("no outputs received")
	}

	party := &Party{
		Index:          partyIndex,
		ReceivedShares: make(map[int]*big.Int),
	}

	// Verify all received shares
	for _, output := range receivedOutputs {
		share := output.Shares[partyIndex]
		if share == nil {
			return nil, fmt.Errorf("missing share from party %d", output.PartyIndex)
		}

		// Verify share using Feldman VSS
		if !VerifyShare(partyIndex, share, output.Commitments) {
			return nil, fmt.Errorf("invalid share from party %d", output.PartyIndex)
		}

		party.ReceivedShares[output.PartyIndex] = share
	}

	// Compute final secret share: x_i = sum of all received shares
	party.SecretShare = big.NewInt(0)
	for _, share := range party.ReceivedShares {
		party.SecretShare = ModAdd(party.SecretShare, share)
	}

	// Compute joint public key: Y = sum of all A_{j,0} (first commitment from each party)
	party.PublicKey = &Point{X: big.NewInt(0), Y: big.NewInt(0)}
	for _, output := range receivedOutputs {
		if party.PublicKey.IsIdentity() {
			party.PublicKey = output.Commitments[0]
		} else {
			party.PublicKey = party.PublicKey.Add(output.Commitments[0])
		}
	}

	// Store commitments (sum of all commitments)
	threshold := len(receivedOutputs[0].Commitments)
	party.Commitments = make([]*Point, threshold)
	for i := 0; i < threshold; i++ {
		party.Commitments[i] = &Point{X: big.NewInt(0), Y: big.NewInt(0)}
		for _, output := range receivedOutputs {
			if party.Commitments[i].IsIdentity() {
				party.Commitments[i] = output.Commitments[i]
			} else {
				party.Commitments[i] = party.Commitments[i].Add(output.Commitments[i])
			}
		}
	}

	return party, nil
}

// RunDistributedKeyGen runs the complete distributed key generation protocol
func RunDistributedKeyGen(threshold, totalParties int) (*KeyGenContext, error) {
	ctx, err := NewKeyGenContext(threshold, totalParties)
	if err != nil {
		return nil, err
	}

	// Round 1: Each party generates polynomial and commitments
	round1Outputs := make([]*KeyGenRound1Output, totalParties)
	for i := 1; i <= totalParties; i++ {
		output, _, err := KeyGenRound1(i, threshold, totalParties)
		if err != nil {
			return nil, fmt.Errorf("party %d round 1 failed: %w", i, err)
		}
		round1Outputs[i-1] = output
	}

	// Round 2: Each party verifies shares and computes final share
	for i := 1; i <= totalParties; i++ {
		party, err := KeyGenRound2(i, round1Outputs)
		if err != nil {
			return nil, fmt.Errorf("party %d round 2 failed: %w", i, err)
		}
		ctx.Parties[i] = party
	}

	// Set the joint public key (same for all parties)
	ctx.PublicKey = ctx.Parties[1].PublicKey

	return ctx, nil
}

// GetPublicKeyShare returns g^{x_i} for party i
func (p *Party) GetPublicKeyShare() *Point {
	return ScalarBaseMult(p.SecretShare)
}

// VerifyKeyShares verifies that all parties have consistent shares
func (ctx *KeyGenContext) VerifyKeyShares() bool {
	// Each party's public key share should satisfy: g^{x_i} matches the combined commitments
	for idx, party := range ctx.Parties {
		if !VerifyShare(idx, party.SecretShare, party.Commitments) {
			return false
		}
	}
	return true
}
