package gg20

import (
	"fmt"
)

// Demo runs a complete demonstration of the GG20 MPC protocol
func Demo() {
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║         GG20 MPC (Multi-Party Computation) Demo            ║")
	fmt.Println("║                Threshold ECDSA Signatures                  ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Configuration: 2-of-3 threshold scheme
	threshold := 2
	totalParties := 3

	// ════════════════════════════════════════════════════════════════
	// PHASE 1: Distributed Key Generation (DKG)
	// ════════════════════════════════════════════════════════════════
	fmt.Println("┌────────────────────────────────────────────────────────────┐")
	fmt.Println("│ PHASE 1: Distributed Key Generation                       │")
	fmt.Println("└────────────────────────────────────────────────────────────┘")
	fmt.Printf("Configuration: %d-of-%d threshold scheme\n\n", threshold, totalParties)

	ctx, err := RunDistributedKeyGen(threshold, totalParties)
	if err != nil {
		fmt.Printf("DKG failed: %v\n", err)
		return
	}

	fmt.Println("✓ Key generation completed successfully!")
	fmt.Printf("\nJoint Public Key:\n")
	fmt.Printf("  X: %s\n", ctx.PublicKey.X.String())
	fmt.Printf("  Y: %s\n", ctx.PublicKey.Y.String())

	fmt.Println("\nSecret Share Distribution:")
	for i := 1; i <= totalParties; i++ {
		share := ctx.Parties[i].SecretShare
		fmt.Printf("  Party %d: %s... (hidden)\n", i, share.String()[:16])
	}

	// Verify key shares
	if ctx.VerifyKeyShares() {
		fmt.Println("\n✓ All key shares verified using Feldman VSS")
	}

	// ════════════════════════════════════════════════════════════════
	// PHASE 2: MPC-based Signature Generation
	// ════════════════════════════════════════════════════════════════
	fmt.Println("\n┌────────────────────────────────────────────────────────────┐")
	fmt.Println("│ PHASE 2: MPC-based Signature Generation                   │")
	fmt.Println("└────────────────────────────────────────────────────────────┘")

	message := []byte("Transfer 100 ETH to 0x742d35Cc6634C0532925a3b844Bc9e7595f...")
	fmt.Printf("Message to sign: %s\n\n", message)

	// Signing with parties 1 and 2
	fmt.Println("Scenario A: Signing with Party 1 and Party 2")
	participants := []int{1, 2}
	sig1, err := RunThresholdSign(message, ctx, participants)
	if err != nil {
		fmt.Printf("Signing failed: %v\n", err)
		return
	}

	fmt.Printf("  Signature generated:\n")
	fmt.Printf("    R: %s\n", sig1.R.String())
	fmt.Printf("    S: %s\n", sig1.S.String())
	fmt.Printf("    V: %d\n", sig1.V)

	if VerifySignature(message, sig1, ctx.PublicKey) {
		fmt.Println("  ✓ Signature verified successfully!")
	}

	// Signing with parties 2 and 3
	fmt.Println("\nScenario B: Signing with Party 2 and Party 3")
	participants2 := []int{2, 3}
	sig2, err := RunThresholdSign(message, ctx, participants2)
	if err != nil {
		fmt.Printf("Signing failed: %v\n", err)
		return
	}

	fmt.Printf("  Signature generated:\n")
	fmt.Printf("    R: %s\n", sig2.R.String())
	fmt.Printf("    S: %s\n", sig2.S.String())

	if VerifySignature(message, sig2, ctx.PublicKey) {
		fmt.Println("  ✓ Signature verified successfully!")
	}

	// Both signatures are valid for the same public key!
	fmt.Println("\n→ Both signatures verify against the same public key,")
	fmt.Println("  demonstrating that any t parties can sign.")

	// ════════════════════════════════════════════════════════════════
	// PHASE 3: Share Refreshing (Proactive Security)
	// ════════════════════════════════════════════════════════════════
	fmt.Println("\n┌────────────────────────────────────────────────────────────┐")
	fmt.Println("│ PHASE 3: Share Refreshing (Proactive Security)            │")
	fmt.Println("└────────────────────────────────────────────────────────────┘")

	fmt.Println("Before refresh - Secret shares:")
	for i := 1; i <= totalParties; i++ {
		fmt.Printf("  Party %d: %s...\n", i, ctx.Parties[i].SecretShare.String()[:16])
	}

	// Perform share refresh
	newCtx, err := RunShareRefresh(ctx)
	if err != nil {
		fmt.Printf("Refresh failed: %v\n", err)
		return
	}

	fmt.Println("\nAfter refresh - Secret shares:")
	for i := 1; i <= totalParties; i++ {
		fmt.Printf("  Party %d: %s...\n", i, newCtx.Parties[i].SecretShare.String()[:16])
	}

	// Verify refresh
	valid, msg := VerifyRefresh(ctx, newCtx)
	if valid {
		fmt.Printf("\n✓ %s\n", msg)
	}

	fmt.Println("\nProperties after refresh:")
	fmt.Printf("  • Public key unchanged: %v\n", ctx.PublicKey.Equal(newCtx.PublicKey))
	fmt.Println("  • All secret shares changed")
	fmt.Println("  • Old shares cannot be used with new shares")

	// Verify signing still works after refresh
	fmt.Println("\nVerifying signing with new shares:")
	newMessage := []byte("New transaction after refresh")
	sig3, err := RunThresholdSign(newMessage, newCtx, []int{1, 3})
	if err != nil {
		fmt.Printf("Signing failed: %v\n", err)
		return
	}

	if VerifySignature(newMessage, sig3, newCtx.PublicKey) {
		fmt.Println("  ✓ Signature with refreshed shares verified!")
	}

	// ════════════════════════════════════════════════════════════════
	// Summary
	// ════════════════════════════════════════════════════════════════
	fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║                        Summary                             ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println("GG20 MPC Protocol successfully demonstrated:")
	fmt.Println("  1. ✓ Distributed Key Generation (3 parties)")
	fmt.Println("  2. ✓ Threshold Signatures (2-of-3)")
	fmt.Println("  3. ✓ Share Refreshing (proactive security)")
	fmt.Println()
	fmt.Println("Key Benefits:")
	fmt.Println("  • No single point of failure (distributed trust)")
	fmt.Println("  • Private key never exists in one place")
	fmt.Println("  • Share refresh protects against gradual compromise")
	fmt.Println("  • Compatible with standard ECDSA verification")
}
