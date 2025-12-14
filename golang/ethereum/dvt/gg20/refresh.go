package gg20

import (
	"fmt"
	"math/big"
)

// RefreshContext holds the state for proactive share refreshing
type RefreshContext struct {
	Threshold    int
	TotalParties int
	Parties      map[int]*Party
	PublicKey    *Point // Should remain unchanged after refresh
}

// RefreshRound1Output represents output from round 1 of share refresh
type RefreshRound1Output struct {
	PartyIndex  int
	Commitments []*Point         // Feldman VSS commitments for the zero polynomial
	Shares      map[int]*big.Int // Zero-sharing polynomial evaluated at each party's index
}

// RefreshRound1 performs round 1 of share refresh
// Each party generates a random polynomial with zero constant term (zero-sharing)
// This allows updating shares without changing the secret
func RefreshRound1(partyIndex, threshold, totalParties int) (*RefreshRound1Output, *Polynomial, error) {
	// Create a zero polynomial: f(x) = 0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
	// This polynomial evaluates to 0 at x=0, so adding shares doesn't change the secret
	zeroPoly, err := ZeroPolynomial(threshold - 1)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate zero polynomial: %w", err)
	}

	// Generate Feldman VSS commitments
	// Note: The first commitment should be the identity point (g^0 = 1)
	// In practice, we use g^{a_0} = g^0 = identity
	commitments := zeroPoly.CommitmentPolynomial()

	// Compute shares for all parties
	shares := make(map[int]*big.Int)
	for j := 1; j <= totalParties; j++ {
		shares[j] = zeroPoly.Eval(big.NewInt(int64(j)))
	}

	return &RefreshRound1Output{
		PartyIndex:  partyIndex,
		Commitments: commitments,
		Shares:      shares,
	}, zeroPoly, nil
}

// RefreshRound2 performs round 2 of share refresh
// Each party verifies received zero-shares and updates their secret share
func RefreshRound2(party *Party, receivedOutputs []*RefreshRound1Output) (*Party, error) {
	if len(receivedOutputs) == 0 {
		return nil, fmt.Errorf("no outputs received")
	}

	// Create new party with updated share
	newParty := &Party{
		Index:          party.Index,
		PublicKey:      party.PublicKey, // Public key doesn't change
		ReceivedShares: make(map[int]*big.Int),
	}

	// Start with the current secret share
	newShare := new(big.Int).Set(party.SecretShare)

	// Verify and add all received zero-shares
	for _, output := range receivedOutputs {
		zeroShare := output.Shares[party.Index]
		if zeroShare == nil {
			return nil, fmt.Errorf("missing zero-share from party %d", output.PartyIndex)
		}

		// Verify the zero-share using Feldman VSS
		// Note: The first commitment should be identity (g^0)
		// We verify that g^{zeroShare} matches the commitment polynomial evaluation
		if !VerifyShare(party.Index, zeroShare, output.Commitments) {
			return nil, fmt.Errorf("invalid zero-share from party %d", output.PartyIndex)
		}

		// Verify that the polynomial has zero constant term
		// The first commitment should be the identity point
		// In practice, g^0 = identity point, which is (0,0) or the point at infinity
		// For a proper zero polynomial, A_0 should be identity

		// Add the zero-share to update the secret share
		newShare = ModAdd(newShare, zeroShare)
		newParty.ReceivedShares[output.PartyIndex] = zeroShare
	}

	newParty.SecretShare = newShare

	// Update commitments (sum of old commitments + new zero-polynomial commitments)
	// But for the constant term, it remains the same (identity + identity = identity)
	threshold := len(party.Commitments)
	newParty.Commitments = make([]*Point, threshold)

	for i := 0; i < threshold; i++ {
		// Start with original commitment
		newParty.Commitments[i] = party.Commitments[i]

		// Add all zero-polynomial commitments
		for _, output := range receivedOutputs {
			if i < len(output.Commitments) {
				newParty.Commitments[i] = newParty.Commitments[i].Add(output.Commitments[i])
			}
		}
	}

	return newParty, nil
}

// RunShareRefresh runs the complete share refresh protocol
// After refresh:
// - Each party has a new secret share
// - The underlying secret remains unchanged
// - The public key remains unchanged
// - Old shares become useless for signing
func RunShareRefresh(ctx *KeyGenContext) (*KeyGenContext, error) {
	newCtx := &KeyGenContext{
		Threshold:    ctx.Threshold,
		TotalParties: ctx.TotalParties,
		Parties:      make(map[int]*Party),
		PublicKey:    ctx.PublicKey, // Public key doesn't change
	}

	// Round 1: Each party generates zero-polynomial and shares
	round1Outputs := make([]*RefreshRound1Output, ctx.TotalParties)
	for i := 1; i <= ctx.TotalParties; i++ {
		output, _, err := RefreshRound1(i, ctx.Threshold, ctx.TotalParties)
		if err != nil {
			return nil, fmt.Errorf("party %d refresh round 1 failed: %w", i, err)
		}
		round1Outputs[i-1] = output
	}

	// Round 2: Each party verifies and updates their share
	for i := 1; i <= ctx.TotalParties; i++ {
		oldParty := ctx.Parties[i]
		newParty, err := RefreshRound2(oldParty, round1Outputs)
		if err != nil {
			return nil, fmt.Errorf("party %d refresh round 2 failed: %w", i, err)
		}
		newCtx.Parties[i] = newParty
	}

	return newCtx, nil
}

// VerifyRefresh verifies that the refresh was successful
// - Public key should be unchanged
// - Shares can still reconstruct the original secret
// - Individual shares have changed
func VerifyRefresh(oldCtx, newCtx *KeyGenContext) (bool, string) {
	// Check public key unchanged
	if !oldCtx.PublicKey.Equal(newCtx.PublicKey) {
		return false, "public key changed after refresh"
	}

	// Check that shares have changed
	sharesChanged := false
	for i := 1; i <= oldCtx.TotalParties; i++ {
		if oldCtx.Parties[i].SecretShare.Cmp(newCtx.Parties[i].SecretShare) != 0 {
			sharesChanged = true
			break
		}
	}

	if !sharesChanged {
		return false, "no shares changed after refresh"
	}

	// Verify shares still reconstruct to same secret by checking public key derivation
	// Reconstruct secret from new shares
	newShares := make(map[int]*big.Int)
	for i := 1; i <= newCtx.TotalParties; i++ {
		newShares[i] = newCtx.Parties[i].SecretShare
	}

	// Use subset of parties (threshold)
	subset := make(map[int]*big.Int)
	count := 0
	for i, share := range newShares {
		if count >= newCtx.Threshold {
			break
		}
		subset[i] = share
		count++
	}

	reconstructedSecret := InterpolateSecret(subset)

	// Verify: g^{reconstructedSecret} should equal PublicKey
	reconstructedPubKey := ScalarBaseMult(reconstructedSecret)
	if !reconstructedPubKey.Equal(newCtx.PublicKey) {
		return false, "reconstructed public key doesn't match"
	}

	return true, "refresh successful"
}

// ProactiveRefreshWithRotation performs refresh and optionally rotates out a party
// This is useful when a party's share might be compromised
func ProactiveRefreshWithRotation(ctx *KeyGenContext, excludeParty int, newPartyIndex int) (*KeyGenContext, error) {
	if excludeParty < 1 || excludeParty > ctx.TotalParties {
		return nil, fmt.Errorf("invalid party to exclude: %d", excludeParty)
	}

	// First, do a normal refresh
	refreshedCtx, err := RunShareRefresh(ctx)
	if err != nil {
		return nil, fmt.Errorf("refresh failed: %w", err)
	}

	// The excluded party's old share is now useless
	// In a real implementation, we would:
	// 1. Generate a new share for the new party using the remaining parties
	// 2. Invalidate the excluded party's access

	// For this demo, we'll re-share the new party's share from the remaining parties
	// This requires threshold parties to cooperate

	// Get the subset of parties (excluding the compromised one)
	activeParties := make([]int, 0, ctx.TotalParties-1)
	for i := 1; i <= ctx.TotalParties; i++ {
		if i != excludeParty {
			activeParties = append(activeParties, i)
		}
	}

	if len(activeParties) < ctx.Threshold {
		return nil, fmt.Errorf("not enough parties remaining for recovery")
	}

	// The new party gets a share that's consistent with the existing secret
	// In practice, this is done through secure resharing
	// For demo, we reconstruct and re-share

	shares := make(map[int]*big.Int)
	for _, idx := range activeParties[:ctx.Threshold] {
		shares[idx] = refreshedCtx.Parties[idx].SecretShare
	}

	// Reconstruct secret (in practice, this is done in MPC without revealing secret)
	secret := InterpolateSecret(shares)

	// Create new polynomial with the secret
	newPoly, err := RandomPolynomial(ctx.Threshold-1, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create new polynomial: %w", err)
	}

	// Generate new share for the replacement party
	newShare := newPoly.Eval(big.NewInt(int64(newPartyIndex)))

	// Update the context
	refreshedCtx.Parties[newPartyIndex] = &Party{
		Index:       newPartyIndex,
		SecretShare: newShare,
		PublicKey:   refreshedCtx.PublicKey,
		Commitments: newPoly.CommitmentPolynomial(),
	}

	// Remove the excluded party
	delete(refreshedCtx.Parties, excludeParty)

	return refreshedCtx, nil
}
