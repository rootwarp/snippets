package main

import (
	"fmt"
	"os"

	logging "github.com/ipfs/go-log"
)

func init() {
	// Set logging level (can be "debug", "info", "warning", "error")
	logging.SetLogLevel("tss-lib", "warning")
}

func main() {
	fmt.Println("=" + string(make([]byte, 60)))
	fmt.Println("MPC Threshold Signature Demo using GG20 (tss-lib)")
	fmt.Println("=" + string(make([]byte, 60)))
	fmt.Println()

	// Step 1: Key Generation
	fmt.Println("STEP 1: Distributed Key Generation")
	fmt.Println("-" + string(make([]byte, 40)))

	config := DefaultConfig()
	fmt.Printf("Configuration: %d parties, threshold t=%d (need t+1=%d parties to sign)\n\n",
		config.PartyCount, config.Threshold, config.Threshold+1)

	keyGenResult, err := RunKeyGeneration(config)
	if err != nil {
		fmt.Printf("Key generation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println()

	// Step 2: Signing with threshold parties
	fmt.Println("STEP 2: Distributed Signing")
	fmt.Println("-" + string(make([]byte, 40)))

	message := []byte("Hello, MPC World!")

	// Sign with parties 0 and 1 (2 parties, meeting threshold+1 = 2)
	signerIndices := []int{0, 1}
	fmt.Printf("Signing with parties %v (threshold requires %d)\n\n",
		[]int{1, 2}, config.Threshold+1) // Display 1-indexed

	sigResult, err := RunSigning(keyGenResult, message, signerIndices)
	if err != nil {
		fmt.Printf("Signing failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println()

	// Step 3: Verify signature
	fmt.Println("STEP 3: Signature Verification")
	fmt.Println("-" + string(make([]byte, 40)))

	valid := VerifySignature(keyGenResult, sigResult)
	if valid {
		fmt.Println("✓ Signature verified successfully!")
	} else {
		fmt.Println("✗ Signature verification failed!")
		os.Exit(1)
	}
	fmt.Println()

	// Step 4: Sign with different party combination
	fmt.Println("STEP 4: Sign with Different Party Combination")
	fmt.Println("-" + string(make([]byte, 40)))

	message2 := []byte("Second message for signing")
	signerIndices2 := []int{1, 2} // Parties 2 and 3
	fmt.Printf("Signing with parties %v\n\n", []int{2, 3})

	sigResult2, err := RunSigning(keyGenResult, message2, signerIndices2)
	if err != nil {
		fmt.Printf("Signing failed: %v\n", err)
		os.Exit(1)
	}

	valid2 := VerifySignature(keyGenResult, sigResult2)
	if valid2 {
		fmt.Println("✓ Second signature verified successfully!")
	} else {
		fmt.Println("✗ Second signature verification failed!")
		os.Exit(1)
	}
	fmt.Println()

	// Step 5: Key Resharing
	fmt.Println("STEP 5: Key Resharing")
	fmt.Println("-" + string(make([]byte, 40)))
	fmt.Println("Resharing keys to new parties (simulating party rotation)")
	fmt.Println()

	reshareResult, err := RunResharing(keyGenResult, nil) // nil uses default (same params)
	if err != nil {
		fmt.Printf("Resharing failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println()

	// Step 6: Sign with new shares
	fmt.Println("STEP 6: Sign with New Shares (After Resharing)")
	fmt.Println("-" + string(make([]byte, 40)))

	message3 := []byte("Message signed with reshared keys")
	signerIndices3 := []int{0, 1}

	sigResult3, err := SignWithNewKeyData(
		reshareResult.NewPartyShares,
		reshareResult.NewPartyIDs,
		reshareResult.NewThreshold,
		message3,
		signerIndices3,
	)
	if err != nil {
		fmt.Printf("Signing with new shares failed: %v\n", err)
		os.Exit(1)
	}

	// Verify using original public key (should still work!)
	valid3 := VerifySignature(keyGenResult, sigResult3)
	if valid3 {
		fmt.Println("✓ Signature with reshared keys verified successfully!")
		fmt.Println("  (Public key preserved after resharing)")
	} else {
		fmt.Println("✗ Signature verification failed!")
		os.Exit(1)
	}
	fmt.Println()

	// Summary
	fmt.Println("=" + string(make([]byte, 60)))
	fmt.Println("SUMMARY")
	fmt.Println("=" + string(make([]byte, 60)))
	fmt.Printf("• Generated threshold keys for %d parties\n", config.PartyCount)
	fmt.Printf("• Threshold: %d (requires %d parties to sign)\n", config.Threshold, config.Threshold+1)
	fmt.Printf("• Successfully signed 3 messages\n")
	fmt.Printf("• Successfully reshared keys to new parties\n")
	fmt.Printf("• Public key preserved across resharing\n")
	fmt.Println()
	fmt.Println("Demo completed successfully! ✓")
}
