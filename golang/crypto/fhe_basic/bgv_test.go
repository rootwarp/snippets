package main

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func TestBGVEncAndDec(t *testing.T) {
	// TODO: Why?
	paramsLit := bgv.ParametersLiteral{ // same one used in the
		LogN:             13,
		LogQ:             []int{42, 33, 33, 33, 33},
		LogP:             []int{44},
		PlaintextModulus: 0x3ee0001,
	}

	params, err := bgv.NewParametersFromLiteral(paramsLit)
	if err != nil {
		panic(err)
	}

	encoder := bgv.NewEncoder(params)
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()

	enc := rlwe.NewEncryptor(params, pk)
	dec := rlwe.NewDecryptor(params, sk)

	plaintext := bgv.NewPlaintext(params, params.MaxLevel())

	randomValue := rand.Uint64() % params.PlaintextModulus()

	// Encrypt
	encoder.Encode([]uint64{randomValue}, plaintext)

	cyphertext, err := enc.EncryptNew(plaintext)
	assert.NoError(t, err)

	// Decrypt
	decrypted := dec.DecryptNew(cyphertext)

	decoded := make([]uint64, 1)
	encoder.Decode(decrypted, decoded)

	assert.Equal(t, randomValue, decoded[0])
}

func TestBGVAdd(t *testing.T) {
	paramsLit := bgv.ParametersLiteral{ // same one used in the
		LogN:             13,
		LogQ:             []int{42, 33, 33, 33, 33},
		LogP:             []int{44},
		PlaintextModulus: 0x3ee0001,
	}

	params, err := bgv.NewParametersFromLiteral(paramsLit)
	if err != nil {
		panic(err)
	}

	encoder := bgv.NewEncoder(params)
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()

	enc := rlwe.NewEncryptor(params, pk)
	dec := rlwe.NewDecryptor(params, sk)
	eval := bgv.NewEvaluator(params, nil)

	plaintext := bgv.NewPlaintext(params, params.MaxLevel())

	randomValue := uint64(5)
	encoder.Encode([]uint64{randomValue}, plaintext)

	plainResult := bgv.NewPlaintext(params, params.MaxLevel())
	encoder.Encode([]uint64{0}, plainResult)

	cypherValue, err := enc.EncryptNew(plaintext)
	assert.NoError(t, err)

	cypherResult, err := enc.EncryptNew(plainResult)
	assert.NoError(t, err)

	_ = enc
	_ = dec
	_ = eval
	_ = cypherValue
	_ = cypherResult

	for i := 0; i < 100000; i++ {
		err = eval.Add(cypherValue, cypherResult, cypherResult)
		assert.NoError(t, err)

		decryptedResult := dec.DecryptNew(cypherResult)
		decodedResult := make([]uint64, 1)
		encoder.Decode(decryptedResult, decodedResult)

		fmt.Println("decodedResult", decodedResult)
	}

	_ = encoder
	_ = enc
	_ = dec
}

// TODO: Bootstrapping.
