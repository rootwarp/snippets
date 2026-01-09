package gg20

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPolynomialEval tests polynomial evaluation
func TestPolynomialEval(t *testing.T) {
	// f(x) = 5 + 3x + 2x^2
	coeffs := []*big.Int{
		big.NewInt(5),
		big.NewInt(3),
		big.NewInt(2),
	}
	poly := NewPolynomial(coeffs)

	// f(0) = 5
	assert.Equal(t, big.NewInt(5).String(), poly.Eval(big.NewInt(0)).String())

	// f(1) = 5 + 3 + 2 = 10
	assert.Equal(t, big.NewInt(10).String(), poly.Eval(big.NewInt(1)).String())

	// f(2) = 5 + 6 + 8 = 19
	assert.Equal(t, big.NewInt(19).String(), poly.Eval(big.NewInt(2)).String())
}

// TestLagrangeInterpolation tests secret reconstruction
func TestLagrangeInterpolation(t *testing.T) {
	secret := big.NewInt(42)

	// Create a polynomial with the secret as constant term
	poly, err := RandomPolynomial(2, secret) // t-1 = 2, so t = 3
	require.NoError(t, err)

	// Generate shares for 5 parties
	shares := make(map[int]*big.Int)
	for i := 1; i <= 5; i++ {
		shares[i] = poly.Eval(big.NewInt(int64(i)))
	}

	// Reconstruct using any 3 shares
	subset := make(map[int]*big.Int)
	subset[1] = shares[1]
	subset[3] = shares[3]
	subset[5] = shares[5]

	recovered := InterpolateSecret(subset)
	assert.Equal(t, secret.String(), recovered.String())

	// Reconstruct using different subset
	subset2 := make(map[int]*big.Int)
	subset2[2] = shares[2]
	subset2[4] = shares[4]
	subset2[5] = shares[5]

	recovered2 := InterpolateSecret(subset2)
	assert.Equal(t, secret.String(), recovered2.String())
}

// TestDistributedKeyGeneration tests the DKG protocol with 3 parties
func TestDistributedKeyGeneration(t *testing.T) {
	const (
		threshold    = 2 // 2-of-3 threshold
		totalParties = 3
	)

	fmt.Println("=== Distributed Key Generation for 3 Parties ===")

	// Run DKG
	ctx, err := RunDistributedKeyGen(threshold, totalParties)
	require.NoError(t, err)

	fmt.Printf("Public Key: (%s, %s)\n", ctx.PublicKey.X.String()[:20]+"...", ctx.PublicKey.Y.String()[:20]+"...")

	// Verify all parties have the same public key
	for i := 1; i <= totalParties; i++ {
		assert.True(t, ctx.PublicKey.Equal(ctx.Parties[i].PublicKey),
			"Party %d has different public key", i)
		fmt.Printf("Party %d secret share: %s...\n", i, ctx.Parties[i].SecretShare.String()[:20])
	}

	// Verify shares using Feldman VSS
	assert.True(t, ctx.VerifyKeyShares(), "Key shares verification failed")

	// Verify that threshold shares can reconstruct the secret
	shares := make(map[int]*big.Int)
	shares[1] = ctx.Parties[1].SecretShare
	shares[2] = ctx.Parties[2].SecretShare

	reconstructedSecret := InterpolateSecret(shares)
	reconstructedPubKey := ScalarBaseMult(reconstructedSecret)

	assert.True(t, reconstructedPubKey.Equal(ctx.PublicKey),
		"Reconstructed public key doesn't match")

	fmt.Println("✓ DKG successful - all parties have consistent shares")
}

// TestMPCSignature tests threshold signature generation
func TestMPCSignature(t *testing.T) {
	const (
		threshold    = 2
		totalParties = 3
	)

	fmt.Println("\n=== MPC-based Signature Generation ===")

	// First, run DKG
	ctx, err := RunDistributedKeyGen(threshold, totalParties)
	require.NoError(t, err)

	// Message to sign
	message := []byte("Hello, Threshold ECDSA!")
	fmt.Printf("Message: %s\n", message)

	// Sign with parties 1 and 2 (threshold = 2)
	participants := []int{1, 2}
	fmt.Printf("Signing parties: %v\n", participants)

	sig, err := RunThresholdSign(message, ctx, participants)
	require.NoError(t, err)

	fmt.Printf("Signature R: %s...\n", sig.R.String()[:20])
	fmt.Printf("Signature S: %s...\n", sig.S.String()[:20])

	// Verify signature
	valid := VerifySignature(message, sig, ctx.PublicKey)
	assert.True(t, valid, "Signature verification failed")

	fmt.Println("✓ Signature verified successfully")

	// Sign with different set of parties (2 and 3)
	participants2 := []int{2, 3}
	fmt.Printf("\nSigning with different parties: %v\n", participants2)

	sig2, err := RunThresholdSign(message, ctx, participants2)
	require.NoError(t, err)

	valid2 := VerifySignature(message, sig2, ctx.PublicKey)
	assert.True(t, valid2, "Signature verification failed for second signing")

	fmt.Println("✓ Second signature verified successfully")

	// Sign with all 3 parties
	participants3 := []int{1, 2, 3}
	fmt.Printf("\nSigning with all parties: %v\n", participants3)

	sig3, err := RunThresholdSign(message, ctx, participants3)
	require.NoError(t, err)

	valid3 := VerifySignature(message, sig3, ctx.PublicKey)
	assert.True(t, valid3, "Signature verification failed for all-party signing")

	fmt.Println("✓ All-party signature verified successfully")
}

// TestShareRefresh tests the proactive share refresh protocol
func TestShareRefresh(t *testing.T) {
	const (
		threshold    = 2
		totalParties = 3
	)

	fmt.Println("\n=== Share Refreshing Process ===")

	// First, run DKG
	ctx, err := RunDistributedKeyGen(threshold, totalParties)
	require.NoError(t, err)

	fmt.Println("Before refresh:")
	for i := 1; i <= totalParties; i++ {
		fmt.Printf("  Party %d share: %s...\n", i, ctx.Parties[i].SecretShare.String()[:20])
	}
	fmt.Printf("  Public Key X: %s...\n", ctx.PublicKey.X.String()[:20])

	// Store old shares for comparison
	oldShares := make(map[int]*big.Int)
	for i := 1; i <= totalParties; i++ {
		oldShares[i] = new(big.Int).Set(ctx.Parties[i].SecretShare)
	}

	// Run share refresh
	newCtx, err := RunShareRefresh(ctx)
	require.NoError(t, err)

	fmt.Println("\nAfter refresh:")
	for i := 1; i <= totalParties; i++ {
		fmt.Printf("  Party %d share: %s...\n", i, newCtx.Parties[i].SecretShare.String()[:20])
	}
	fmt.Printf("  Public Key X: %s...\n", newCtx.PublicKey.X.String()[:20])

	// Verify refresh was successful
	valid, msg := VerifyRefresh(ctx, newCtx)
	assert.True(t, valid, msg)

	// Verify shares have changed
	for i := 1; i <= totalParties; i++ {
		assert.NotEqual(t, oldShares[i].String(), newCtx.Parties[i].SecretShare.String(),
			"Party %d share should have changed", i)
	}

	fmt.Println("✓ Shares successfully changed")

	// Verify public key unchanged
	assert.True(t, ctx.PublicKey.Equal(newCtx.PublicKey), "Public key should be unchanged")
	fmt.Println("✓ Public key unchanged")

	// Verify signing still works with new shares
	message := []byte("Message after refresh")
	sig, err := RunThresholdSign(message, newCtx, []int{1, 2})
	require.NoError(t, err)

	valid2 := VerifySignature(message, sig, newCtx.PublicKey)
	assert.True(t, valid2, "Signature should verify after refresh")

	fmt.Println("✓ Signing works with refreshed shares")

	// Verify old shares can still reconstruct (before they would be discarded)
	oldSharesMap := make(map[int]*big.Int)
	for i := 1; i <= threshold; i++ {
		oldSharesMap[i] = oldShares[i]
	}
	oldSecret := InterpolateSecret(oldSharesMap)
	oldPubKey := ScalarBaseMult(oldSecret)
	assert.True(t, oldPubKey.Equal(ctx.PublicKey), "Old shares should still reconstruct to same key")

	fmt.Println("✓ Old shares still valid (should be discarded in practice)")
}

// TestMultipleRefreshCycles tests multiple consecutive refresh cycles
func TestMultipleRefreshCycles(t *testing.T) {
	const (
		threshold    = 2
		totalParties = 3
		numCycles    = 3
	)

	fmt.Println("\n=== Multiple Refresh Cycles ===")

	ctx, err := RunDistributedKeyGen(threshold, totalParties)
	require.NoError(t, err)

	originalPubKey := ctx.PublicKey

	for cycle := 1; cycle <= numCycles; cycle++ {
		fmt.Printf("\nRefresh cycle %d:\n", cycle)

		newCtx, err := RunShareRefresh(ctx)
		require.NoError(t, err)

		// Verify public key unchanged
		assert.True(t, originalPubKey.Equal(newCtx.PublicKey),
			"Public key changed in cycle %d", cycle)

		// Verify signing works
		message := []byte(fmt.Sprintf("Message for cycle %d", cycle))
		sig, err := RunThresholdSign(message, newCtx, []int{1, 3})
		require.NoError(t, err)

		valid := VerifySignature(message, sig, newCtx.PublicKey)
		assert.True(t, valid, "Signature failed in cycle %d", cycle)

		fmt.Printf("  ✓ Cycle %d: signing verified\n", cycle)

		ctx = newCtx
	}

	fmt.Println("\n✓ All refresh cycles completed successfully")
}

// TestFeldmanVSS tests Feldman Verifiable Secret Sharing
func TestFeldmanVSS(t *testing.T) {
	const (
		threshold    = 2
		totalParties = 3
	)

	fmt.Println("\n=== Feldman VSS Verification ===")

	// Generate a polynomial
	secret, err := RandomScalar()
	require.NoError(t, err)

	poly, err := RandomPolynomial(threshold-1, secret)
	require.NoError(t, err)

	// Create commitments
	commitments := poly.CommitmentPolynomial()
	fmt.Printf("Generated %d commitments\n", len(commitments))

	// Generate and verify shares
	for i := 1; i <= totalParties; i++ {
		share := poly.Eval(big.NewInt(int64(i)))
		valid := VerifyShare(i, share, commitments)
		assert.True(t, valid, "Share verification failed for party %d", i)
		fmt.Printf("  Party %d share verified ✓\n", i)
	}

	// Test with invalid share
	invalidShare := big.NewInt(12345)
	validInvalid := VerifyShare(1, invalidShare, commitments)
	assert.False(t, validInvalid, "Invalid share should not verify")
	fmt.Println("  Invalid share correctly rejected ✓")
}

// TestSignatureWithDifferentMessages tests signing different messages
func TestSignatureWithDifferentMessages(t *testing.T) {
	const (
		threshold    = 2
		totalParties = 3
	)

	ctx, err := RunDistributedKeyGen(threshold, totalParties)
	require.NoError(t, err)

	messages := []string{
		"Hello World",
		"",
		"A longer message that contains more data to be signed",
		"Special chars: !@#$%^&*()",
		string([]byte{0x00, 0x01, 0x02, 0xff}), // Binary data
	}

	participants := []int{1, 2}

	for _, msg := range messages {
		sig, err := RunThresholdSign([]byte(msg), ctx, participants)
		require.NoError(t, err)

		valid := VerifySignature([]byte(msg), sig, ctx.PublicKey)
		assert.True(t, valid, "Signature failed for message: %v", msg)
	}
}

// TestThresholdNotMet tests that signing fails with insufficient parties
func TestThresholdNotMet(t *testing.T) {
	const (
		threshold    = 3
		totalParties = 5
	)

	ctx, err := RunDistributedKeyGen(threshold, totalParties)
	require.NoError(t, err)

	message := []byte("Test message")

	// Try to sign with fewer than threshold parties
	participants := []int{1, 2} // Only 2 parties, but threshold is 3

	_, err = NewSignContext(message, participants, ctx)
	assert.Error(t, err, "Should fail with insufficient parties")
}

// Example demonstrates the complete GG20 workflow
func Example() {
	// 1. Distributed Key Generation for 3 parties (2-of-3 threshold)
	fmt.Println("Step 1: Distributed Key Generation")
	ctx, _ := RunDistributedKeyGen(2, 3)
	fmt.Printf("Public Key generated: (%s...)\n\n", ctx.PublicKey.X.String()[:16])

	// 2. Threshold Signing
	fmt.Println("Step 2: Threshold Signing")
	message := []byte("Transaction data")
	sig, _ := RunThresholdSign(message, ctx, []int{1, 2})
	fmt.Printf("Signature: R=%s..., S=%s...\n\n", sig.R.String()[:16], sig.S.String()[:16])

	// 3. Verify Signature
	fmt.Println("Step 3: Verify Signature")
	valid := VerifySignature(message, sig, ctx.PublicKey)
	fmt.Printf("Signature valid: %v\n\n", valid)

	// 4. Share Refresh
	fmt.Println("Step 4: Share Refresh")
	newCtx, _ := RunShareRefresh(ctx)
	fmt.Printf("Shares refreshed, public key unchanged: %v\n", ctx.PublicKey.Equal(newCtx.PublicKey))
}

// BenchmarkKeyGen benchmarks key generation
func BenchmarkKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = RunDistributedKeyGen(2, 3)
	}
}

// BenchmarkSign benchmarks signing
func BenchmarkSign(b *testing.B) {
	ctx, _ := RunDistributedKeyGen(2, 3)
	message := []byte("Benchmark message")
	participants := []int{1, 2}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = RunThresholdSign(message, ctx, participants)
	}
}

// BenchmarkRefresh benchmarks share refresh
func BenchmarkRefresh(b *testing.B) {
	ctx, _ := RunDistributedKeyGen(2, 3)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx, _ = RunShareRefresh(ctx)
	}
}
