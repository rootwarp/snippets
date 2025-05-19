package main

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func main() {
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
	// rlk := kgen.GenRelinearizationKeyNew(sk, 1)

	enc := rlwe.NewEncryptor(params, pk)
	dec := rlwe.NewDecryptor(params, sk)
	eval := bgv.NewEvaluator(params, nil)
	// encod := heint.NewEncoder(params) // SIMD encoder for integers

	ptA := bgv.NewPlaintext(params, params.MaxLevel())
	ptB := bgv.NewPlaintext(params, params.MaxLevel())

	encoder.Encode([]uint64{123}, ptA)
	encoder.Encode([]uint64{456}, ptB)

	ctA, _ := enc.EncryptNew(ptA)
	ctB, _ := enc.EncryptNew(ptB)

	ctOut := bgv.NewCiphertext(params, 1, params.MaxLevel())

	// Addition
	err = eval.Add(ctA, ctB, ctOut)
	if err != nil {
		panic(err)
	}

	ptA2 := dec.DecryptNew(ctA)
	ptB2 := dec.DecryptNew(ctB)
	ptOut2 := dec.DecryptNew(ctOut)

	ptA2Res := make([]uint64, 2)
	ptB2Res := make([]uint64, 2)
	ptOut2Res := make([]uint64, 2)

	err = encoder.Decode(ptA2, ptA2Res)
	if err != nil {
		panic(err)
	}

	err = encoder.Decode(ptB2, ptB2Res)
	if err != nil {
		panic(err)
	}

	err = encoder.Decode(ptOut2, ptOut2Res)
	if err != nil {
		panic(err)
	}

	fmt.Println(ptA2Res[0])
	fmt.Println(ptB2Res[0])
	fmt.Println(ptOut2Res[0])

	// fmt.Println(ptOut2.Value[0])

	err = eval.Mul(ctA, ctB, ctOut)
	if err != nil {
		panic(err)
	}

	ptA3 := dec.DecryptNew(ctA)
	ptB3 := dec.DecryptNew(ctB)
	ptOut3 := dec.DecryptNew(ctOut)

	ptA3Res := make([]uint64, 2)
	ptB3Res := make([]uint64, 2)
	ptOut3Res := make([]uint64, 2)

	err = encoder.Decode(ptA3, ptA3Res)
	if err != nil {
		panic(err)
	}

	err = encoder.Decode(ptB3, ptB3Res)
	if err != nil {
		panic(err)
	}

	err = encoder.Decode(ptOut3, ptOut3Res)
	if err != nil {
		panic(err)
	}

	fmt.Println(ptA3Res[0])
	fmt.Println(ptB3Res[0])
	fmt.Println(ptOut3Res[0])

	fmt.Println("Max level", params.MaxLevel())

	// ctA := enc.EncryptNew(ptA)
	// ctB := enc.EncryptNew(ptB)

	// ctOut := eval.Add(ctA, ctB)
	// ptOut := dec.DecryptNew(ctOut)

}
