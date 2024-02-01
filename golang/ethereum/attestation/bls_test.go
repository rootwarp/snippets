package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/stretchr/testify/assert"
)

func init() {
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)
}

func TestBLS_SimpleAggregation(t *testing.T) {
	nTest := 10
	testMsg := "hello world"

	privateKeys := make([]*bls.SecretKey, nTest)
	publicKeys := make([]*bls.PublicKey, nTest)

	for i := 0; i < nTest; i++ {
		privateKeys[i] = &bls.SecretKey{}
		privateKeys[i].SetByCSPRNG()

		publicKeys[i] = privateKeys[i].GetPublicKey()
	}

	// Create signatures.
	signatures := make([]*bls.Sign, nTest)
	for i, sk := range privateKeys {
		signatures[i] = sk.Sign(testMsg)
	}

	// Verify signatures.
	for i, sig := range signatures {
		assert.True(t, sig.Verify(publicKeys[i], testMsg))
	}

	// Aggregate signatures.
	aggSig := bls.Sign{}
	for _, sig := range signatures {
		aggSig.Add(sig)
	}

	// Create a new slice to convert []*bls.PublicKey to []bls.PublicKey
	pubKeys := make([]bls.PublicKey, nTest)
	for i, pk := range publicKeys {
		pubKeys[i] = *pk
	}

	testMsgs := make([][]byte, nTest)
	for i := 0; i < nTest; i++ {
		testMsgs[i] = []byte(testMsg)
	}

	// All signatures can be verified by with one aggregated signature.
	assert.True(t, aggSig.VerifyAggregateHashes(pubKeys, testMsgs))
	assert.True(t, aggSig.FastAggregateVerify(pubKeys, []byte(testMsg)))
}

func TestBLS_VerifySingleSlotSingleCommittee(t *testing.T) {
	var (
		blockNo        = 8165556
		committeeIndex = Index(18)
	)

	block, err := fixtureLoadBeaconBlock(blockNo + 1)

	assert.Nil(t, err)

	// Get Attestations for chosen committee index.
	attestations := block.Data.Message.Body.FindAttestationByIndex(committeeIndex)

	for _, att := range attestations {
		assert.Equal(t, committeeIndex, att.Data.Index)
	}

	// Choose second attestation because it aggregated small number of signatures.
	attestation := attestations[1]

	//
	// Create signing data.
	//

	// https://eth2book.info/capella/part3/containers/state/
	genesisValidatorRoot, err := hex.DecodeString("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")

	var genesisValidatorRootHash [32]byte
	copy(genesisValidatorRootHash[:], genesisValidatorRoot)

	forkData := ForkData{
		CurrentVersion:        CAPELLA_FORK_VERSION,
		GenesisValidatorsRoot: genesisValidatorRootHash,
	}

	forkDataRoot, err := forkData.HashTreeRoot()

	domainData := []byte{}
	domainData = append(domainData, DOMAIN_TYPE_ATTESTER...)
	domainData = append(domainData, forkDataRoot[:28]...)

	// create signing data and signing root.
	attestationDataHash, err := attestation.Data.HashTreeRoot()
	signingData := SigningData{
		ObjectRoot: attestationDataHash,
		Domain:     Hash(domainData),
	}

	signingDataHash, err := signingData.HashTreeRoot()

	// =====

	// Get Committee
	committee, err := fixtureLoadCommittee(Slot(blockNo), committeeIndex)

	validators := []*Validator{}
	publicKeys := []bls.PublicKey{}
	for _, n := range attestation.AggregationBits.ToIndex() {
		if n > len(committee.Validators)-1 {
			continue
		}

		validator, err := fixtureLoadValidator(Slot(blockNo), committee.Validators[n])
		assert.Nil(t, err)

		validators = append(validators, validator)
		pubkeyStr := validator.Pubkey
		pk := bls.PublicKey{}
		pk.DeserializeHexStr(strings.TrimPrefix(pubkeyStr, "0x"))

		publicKeys = append(publicKeys, pk)
	}

	aggSigStr := attestation.Signature
	aggSig := bls.Sign{}
	aggSig.DeserializeHexStr(strings.TrimPrefix(aggSigStr, "0x"))

	isValid := aggSig.FastAggregateVerify(publicKeys, signingDataHash[:])

	assert.True(t, isValid)
}
