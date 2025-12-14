package main

import (
	"testing"
	"time"

	logging "github.com/ipfs/go-log"
)

func init() {
	logging.SetLogLevel("tss-lib", "error")
}

// TestKeyGeneration tests distributed key generation for 3 parties
func TestKeyGeneration(t *testing.T) {
	config := DefaultConfig()
	
	t.Logf("Testing key generation with %d parties, threshold %d", config.PartyCount, config.Threshold)
	
	result, err := RunKeyGeneration(config)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Verify results
	if result.PublicKey == nil {
		t.Fatal("Public key X is nil")
	}
	if result.PublicKeyY == nil {
		t.Fatal("Public key Y is nil")
	}
	if len(result.PartyShares) != config.PartyCount {
		t.Fatalf("Expected %d party shares, got %d", config.PartyCount, len(result.PartyShares))
	}

	t.Logf("Key generation successful. Public key X (first 32 chars): %s...", result.PublicKey.Text(16)[:32])
}

// TestSigning tests distributed signing with threshold parties
func TestSigning(t *testing.T) {
	config := DefaultConfig()
	
	// First generate keys
	keyGenResult, err := RunKeyGeneration(config)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Test signing with exactly threshold+1 parties
	message := []byte("Test message for signing")
	signerIndices := []int{0, 1} // 2 parties (threshold+1)
	
	t.Logf("Testing signing with parties %v", signerIndices)
	
	sigResult, err := RunSigning(keyGenResult, message, signerIndices)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	// Verify signature
	valid := VerifySignature(keyGenResult, sigResult)
	if !valid {
		t.Fatal("Signature verification failed")
	}

	t.Log("Signing and verification successful")
}

// TestSigningDifferentParties tests signing with different party combinations
func TestSigningDifferentParties(t *testing.T) {
	config := DefaultConfig()
	
	keyGenResult, err := RunKeyGeneration(config)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	testCases := []struct {
		name    string
		signers []int
	}{
		{"Parties 1,2", []int{0, 1}},
		{"Parties 2,3", []int{1, 2}},
		{"Parties 1,3", []int{0, 2}},
		{"All parties", []int{0, 1, 2}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			message := []byte("Test message: " + tc.name)
			sigResult, err := RunSigning(keyGenResult, message, tc.signers)
			if err != nil {
				t.Fatalf("Signing failed: %v", err)
			}

			valid := VerifySignature(keyGenResult, sigResult)
			if !valid {
				t.Fatal("Signature verification failed")
			}
		})
	}
}

// TestSigningBelowThreshold tests that signing fails with insufficient parties
func TestSigningBelowThreshold(t *testing.T) {
	config := DefaultConfig()
	
	keyGenResult, err := RunKeyGeneration(config)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Try to sign with only 1 party (below threshold+1)
	message := []byte("This should fail")
	signerIndices := []int{0} // Only 1 party
	
	_, err = RunSigning(keyGenResult, message, signerIndices)
	if err == nil {
		t.Fatal("Expected signing to fail with insufficient parties")
	}
	
	t.Logf("Correctly rejected signing with insufficient parties: %v", err)
}

// TestResharing tests key resharing functionality
func TestResharing(t *testing.T) {
	config := DefaultConfig()
	
	// Generate initial keys
	keyGenResult, err := RunKeyGeneration(config)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Reshare to same number of parties
	reshareResult, err := RunResharing(keyGenResult, nil)
	if err != nil {
		t.Fatalf("Resharing failed: %v", err)
	}

	// Verify public key is preserved
	for i, share := range reshareResult.NewPartyShares {
		if share.ECDSAPub.X().Cmp(keyGenResult.PublicKey) != 0 {
			t.Fatalf("Public key X mismatch for new party %d", i)
		}
		if share.ECDSAPub.Y().Cmp(keyGenResult.PublicKeyY) != 0 {
			t.Fatalf("Public key Y mismatch for new party %d", i)
		}
	}

	// Sign with new shares
	message := []byte("Message signed with reshared keys")
	sigResult, err := SignWithNewKeyData(
		reshareResult.NewPartyShares,
		reshareResult.NewPartyIDs,
		reshareResult.NewThreshold,
		message,
		[]int{0, 1},
	)
	if err != nil {
		t.Fatalf("Signing with new shares failed: %v", err)
	}

	// Verify using original public key
	valid := VerifySignature(keyGenResult, sigResult)
	if !valid {
		t.Fatal("Signature with reshared keys failed verification")
	}

	t.Log("Resharing and subsequent signing successful")
}

// TestRefreshShares tests share refresh (same parties, new shares)
func TestRefreshShares(t *testing.T) {
	config := DefaultConfig()
	
	keyGenResult, err := RunKeyGeneration(config)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Refresh shares
	refreshResult, err := RefreshShares(keyGenResult)
	if err != nil {
		t.Fatalf("Share refresh failed: %v", err)
	}

	// Verify we can still sign
	message := []byte("Message after share refresh")
	sigResult, err := SignWithNewKeyData(
		refreshResult.NewPartyShares,
		refreshResult.NewPartyIDs,
		refreshResult.NewThreshold,
		message,
		[]int{0, 1},
	)
	if err != nil {
		t.Fatalf("Signing after refresh failed: %v", err)
	}

	valid := VerifySignature(keyGenResult, sigResult)
	if !valid {
		t.Fatal("Signature after refresh failed verification")
	}

	t.Log("Share refresh successful")
}

// TestGeneratePartyIDs tests party ID generation
func TestGeneratePartyIDs(t *testing.T) {
	partyIDs := GeneratePartyIDs(3)
	
	if len(partyIDs) != 3 {
		t.Fatalf("Expected 3 party IDs, got %d", len(partyIDs))
	}

	// Verify IDs are unique
	seen := make(map[string]bool)
	for _, id := range partyIDs {
		if seen[id.Id] {
			t.Fatalf("Duplicate party ID: %s", id.Id)
		}
		seen[id.Id] = true
	}

	t.Logf("Generated party IDs: %v", partyIDs)
}

// BenchmarkKeyGeneration benchmarks key generation
func BenchmarkKeyGeneration(b *testing.B) {
	config := DefaultConfig()
	
	for i := 0; i < b.N; i++ {
		_, err := RunKeyGeneration(config)
		if err != nil {
			b.Fatalf("Key generation failed: %v", err)
		}
	}
}

// BenchmarkSigning benchmarks signing (excluding key generation)
func BenchmarkSigning(b *testing.B) {
	config := DefaultConfig()
	keyGenResult, err := RunKeyGeneration(config)
	if err != nil {
		b.Fatalf("Key generation failed: %v", err)
	}

	message := []byte("Benchmark message")
	signerIndices := []int{0, 1}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := RunSigning(keyGenResult, message, signerIndices)
		if err != nil {
			b.Fatalf("Signing failed: %v", err)
		}
	}
}

// TestEndToEnd runs a complete end-to-end test
func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping end-to-end test in short mode")
	}

	start := time.Now()
	
	// 1. Key Generation
	t.Log("Step 1: Key Generation")
	config := DefaultConfig()
	keyGenResult, err := RunKeyGeneration(config)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}
	t.Logf("Key generation completed in %v", time.Since(start))

	// 2. Sign multiple messages
	t.Log("Step 2: Signing messages")
	messages := [][]byte{
		[]byte("First message"),
		[]byte("Second message"),
		[]byte("Third message"),
	}

	for i, msg := range messages {
		sigResult, err := RunSigning(keyGenResult, msg, []int{0, 1})
		if err != nil {
			t.Fatalf("Signing message %d failed: %v", i, err)
		}
		if !VerifySignature(keyGenResult, sigResult) {
			t.Fatalf("Verification of message %d failed", i)
		}
	}
	t.Logf("Signed and verified %d messages", len(messages))

	// 3. Reshare
	t.Log("Step 3: Key Resharing")
	reshareStart := time.Now()
	reshareResult, err := RunResharing(keyGenResult, nil)
	if err != nil {
		t.Fatalf("Resharing failed: %v", err)
	}
	t.Logf("Resharing completed in %v", time.Since(reshareStart))

	// 4. Sign with new shares
	t.Log("Step 4: Signing with new shares")
	newSigResult, err := SignWithNewKeyData(
		reshareResult.NewPartyShares,
		reshareResult.NewPartyIDs,
		reshareResult.NewThreshold,
		[]byte("Message with new shares"),
		[]int{0, 1},
	)
	if err != nil {
		t.Fatalf("Signing with new shares failed: %v", err)
	}
	if !VerifySignature(keyGenResult, newSigResult) {
		t.Fatal("Verification with new shares failed")
	}

	t.Logf("End-to-end test completed in %v", time.Since(start))
}
