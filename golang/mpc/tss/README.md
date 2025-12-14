# MPC Threshold Signatures using GG20 (tss-lib)

This project demonstrates Multi-Party Computation (MPC) based threshold signatures using the GG20 cryptographic scheme implemented by the [tss-lib](https://github.com/bnb-chain/tss-lib) library.

## Overview

Threshold signatures allow a group of parties to jointly sign a message without any single party having access to the complete private key. This implementation uses the GG20 protocol which provides:

- **Distributed Key Generation (DKG)**: Generate a shared key across multiple parties
- **Threshold Signing**: Sign messages with a threshold number of parties
- **Key Resharing**: Rotate keys or change the party composition while preserving the public key

## Configuration

Default configuration:
- **3 parties**: Three participants in the MPC protocol
- **Threshold t=1**: Requires t+1=2 parties to sign (2-of-3 scheme)

## Files

- `main.go` - Main demonstration program
- `party.go` - Party management and message routing
- `keygen.go` - Distributed key generation implementation
- `signing.go` - Threshold signing implementation
- `resharing.go` - Key resharing/rotation implementation
- `mpc_test.go` - Comprehensive test suite

## Usage

### Build and Run

```bash
# Install dependencies and build
make deps
make build

# Run the demo
make run
# or
./mpc-tss
```

### Running Tests

```bash
# Run all tests (may take several minutes)
make test

# Run specific tests
make test-keygen
make test-signing
make test-resharing

# Run benchmarks
make bench
```

## Demo Output

The demo program performs the following steps:

1. **Distributed Key Generation**: Generate threshold keys for 3 parties
2. **Distributed Signing**: Sign a message with 2 parties
3. **Signature Verification**: Verify the signature using the public key
4. **Sign with Different Parties**: Sign with a different party combination
5. **Key Resharing**: Reshare keys to new parties
6. **Sign with New Shares**: Sign using the reshared keys

## How It Works

### Key Generation

Each party generates a share of the private key through a multi-round protocol:
1. Each party generates pre-parameters (safe primes for Paillier encryption)
2. Parties exchange commitments and shares
3. Each party ends up with their share and the shared public key

### Signing

Only a threshold number of parties (t+1) need to participate:
1. Parties exchange protocol messages
2. Each party contributes their share to create a signature
3. The resulting signature is valid for the shared public key

### Resharing

Resharing allows changing the party composition or refreshing shares:
1. Old parties share their secrets with new parties
2. New parties receive new shares
3. The public key remains the same

## Security Notes

- This is a demonstration implementation
- In production, use secure channels for message transport
- Pre-parameters should be generated offline and stored securely
- Consider using hardware security modules (HSMs) for key storage

## Dependencies

- [tss-lib](https://github.com/bnb-chain/tss-lib) - Threshold signature library
- [go-log](https://github.com/ipfs/go-log) - Logging library

## References

- [GG20 Paper](https://eprint.iacr.org/2020/540) - "One Round Threshold ECDSA with Identifiable Abort"
- [tss-lib Documentation](https://github.com/bnb-chain/tss-lib)
