package gg20

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
)

// SignContext holds the state for threshold signing
type SignContext struct {
	Message      []byte         // Message to sign
	MessageHash  *big.Int       // Hash of the message
	Participants []int          // Indices of signing parties
	Threshold    int            // Minimum parties needed
	Parties      map[int]*Party // Participating parties
	PublicKey    *Point         // Joint public key
}

// SignRound1Output represents output from round 1 of signing
type SignRound1Output struct {
	PartyIndex int
	KShare     *big.Int // k_i: party's share of nonce k
	GammaShare *big.Int // γ_i: blinding factor for computing k^{-1}
	KPoint     *Point   // K_i = g^{k_i}: commitment to k share
	GammaPoint *Point   // Γ_i = g^{γ_i}: commitment to gamma
}

// SignRound2Output represents output from round 2 of signing
type SignRound2Output struct {
	PartyIndex int
	DeltaShare *big.Int // δ_i: party's share of k * γ
	SigmaShare *big.Int // σ_i: party's share of k * w (w = λ*x, weighted secret)
}

// SignRound3Output represents output from round 3 of signing
type SignRound3Output struct {
	PartyIndex  int
	PartialSigS *big.Int // s_i: partial signature component
}

// Signature represents an ECDSA signature
type Signature struct {
	R *big.Int
	S *big.Int
	V int // Recovery ID
}

// NewSignContext creates a new signing context
func NewSignContext(message []byte, participants []int, ctx *KeyGenContext) (*SignContext, error) {
	if len(participants) < ctx.Threshold {
		return nil, fmt.Errorf("not enough participants: need %d, got %d", ctx.Threshold, len(participants))
	}

	parties := make(map[int]*Party)
	for _, idx := range participants {
		party, ok := ctx.Parties[idx]
		if !ok {
			return nil, fmt.Errorf("party %d not found", idx)
		}
		parties[idx] = party
	}

	return &SignContext{
		Message:      message,
		MessageHash:  HashToScalar(message),
		Participants: participants,
		Threshold:    ctx.Threshold,
		Parties:      parties,
		PublicKey:    ctx.PublicKey,
	}, nil
}

// SignRound1 generates random nonce share k_i and blinding factor γ_i
func SignRound1(partyIndex int) (*SignRound1Output, error) {
	kShare, err := RandomScalar()
	if err != nil {
		return nil, fmt.Errorf("failed to generate k_i: %w", err)
	}

	gammaShare, err := RandomScalar()
	if err != nil {
		return nil, fmt.Errorf("failed to generate γ_i: %w", err)
	}

	return &SignRound1Output{
		PartyIndex: partyIndex,
		KShare:     kShare,
		GammaShare: gammaShare,
		KPoint:     ScalarBaseMult(kShare),
		GammaPoint: ScalarBaseMult(gammaShare),
	}, nil
}

// SignRound2 computes the multiplicative shares using simulated MtA
// In real GG20, MtA uses Paillier encryption to compute products securely
func SignRound2(partyIndex int, myRound1 *SignRound1Output, allRound1 []*SignRound1Output, secretShare *big.Int) (*SignRound2Output, error) {
	// Get participating party indices for Lagrange coefficient
	parties := make([]int, len(allRound1))
	for i, r := range allRound1 {
		parties[i] = r.PartyIndex
	}

	// Compute Lagrange coefficient: λ_i
	lambda := LagrangeCoefficient(partyIndex, parties)

	// Weighted secret share: w_i = λ_i * x_i
	weightedSecret := ModMul(lambda, secretShare)

	// === Simulated MtA for δ = k * γ ===
	// In real GG20: MtA(k_i, γ_j) produces shares α_ij + β_ij = k_i * γ_j
	// Party i gets α_ij, party j gets β_ij
	// Each party's delta share: δ_i = k_i * γ_i + Σ_{j≠i} (α_ij + β_ji)
	//
	// For simulation, we compute the full product and distribute shares

	// Compute total k and γ (in practice, these are never computed directly)
	k := big.NewInt(0)
	gamma := big.NewInt(0)
	for _, r := range allRound1 {
		k = ModAdd(k, r.KShare)
		gamma = ModAdd(gamma, r.GammaShare)
	}

	// Compute δ = k * γ and distribute as additive shares
	kGamma := ModMul(k, gamma)

	// Distribute δ as additive shares (simulated MtA output)
	// Last party gets the remainder to ensure sum equals kGamma
	deltaShare := big.NewInt(0)
	isLast := partyIndex == allRound1[len(allRound1)-1].PartyIndex

	if isLast {
		// Last party gets the remainder
		otherSum := big.NewInt(0)
		for _, r := range allRound1[:len(allRound1)-1] {
			// Deterministic share based on k_i * γ (simplified)
			share := ModMul(r.KShare, gamma)
			otherSum = ModAdd(otherSum, share)
		}
		deltaShare = ModSub(kGamma, otherSum)
	} else {
		// Other parties get k_i * γ as their share
		deltaShare = ModMul(myRound1.KShare, gamma)
	}

	// === Simulated MtA for σ = k * w ===
	// σ_i is party i's share of k * (Σ λ_j * x_j) = k * x
	// Each party computes: σ_i = k_i * w_i + MtA contributions

	// For simulation: σ_i = k * w_i (since k is known in simulation)
	sigmaShare := ModMul(k, weightedSecret)

	return &SignRound2Output{
		PartyIndex: partyIndex,
		DeltaShare: deltaShare,
		SigmaShare: sigmaShare,
	}, nil
}

// SignRound3 computes the partial signature
func SignRound3(
	partyIndex int,
	myRound1 *SignRound1Output,
	allRound1 []*SignRound1Output,
	myRound2 *SignRound2Output,
	allRound2 []*SignRound2Output,
	messageHash *big.Int,
) (*SignRound3Output, *Point, error) {

	// Compute R = Σ K_i = g^{Σ k_i} = g^k
	var R *Point
	for _, r1 := range allRound1 {
		if R == nil {
			R = NewPoint(r1.KPoint.X, r1.KPoint.Y)
		} else {
			R = R.Add(r1.KPoint)
		}
	}

	// Compute δ = Σ δ_i = k * γ
	delta := big.NewInt(0)
	for _, r2 := range allRound2 {
		delta = ModAdd(delta, r2.DeltaShare)
	}

	// Compute k^{-1} using: k^{-1} = γ * δ^{-1}
	// Since δ = k * γ, we have δ^{-1} = (k * γ)^{-1}
	// And γ * δ^{-1} = γ / (k * γ) = 1/k = k^{-1}
	deltaInv := ModInverse(delta)

	// Compute r = R.x mod n
	r := new(big.Int).Mod(R.X, N)

	// === Compute partial signature ===
	// Standard ECDSA: s = k^{-1} * (m + r * x)
	// For threshold: s = k^{-1} * m + k^{-1} * r * x
	//              = k^{-1} * m + r * k^{-1} * Σ(λ_i * x_i)
	//
	// Each party computes:
	// s_i = γ_i * δ^{-1} * m + r * σ_i * δ^{-1}
	//     = δ^{-1} * (γ_i * m + r * σ_i)
	//
	// Sum: Σ s_i = δ^{-1} * (γ * m + r * σ)
	//           = δ^{-1} * (γ * m + r * k * x)
	//           = γ/δ * m + r * k * x / δ
	//           = m/k + r * x / (k * γ) * k
	//           = m/k + r * x / γ (WRONG)
	//
	// Correct approach: use σ_i properly
	// s_i = δ^{-1} * (γ_i * m + r * σ_i)
	// where σ_i sums to k * x (not k_i * w_i)
	//
	// Simplified for simulation:

	// Compute γ (in practice, this would be distributed)
	gamma := big.NewInt(0)
	for _, r1 := range allRound1 {
		gamma = ModAdd(gamma, r1.GammaShare)
	}

	// k^{-1} = γ * δ^{-1}
	kInv := ModMul(gamma, deltaInv)

	// Compute σ = Σ σ_i = k * x
	sigma := big.NewInt(0)
	for _, r2 := range allRound2 {
		sigma = ModAdd(sigma, r2.SigmaShare)
	}

	// Full signature: s = k^{-1} * (m + r * x)
	// Direct computation: s = kInv * (m + r * x)
	// We need x = σ / k, but we don't have k directly
	// However, kInv = γ/δ, and σ = k*x
	// So: s = (γ/δ) * (m + r * σ/k)
	//      = γ*m/δ + r*γ*σ/(δ*k)
	//      = γ*m/δ + r*γ*x/δ  (since σ/k = x)
	//      = (γ/δ) * (m + r*x)
	//      = kInv * (m + r*x) ✓

	// So we need σ/k. Since δ = k*γ, we have k = δ/γ
	// σ/k = σ * γ / δ = σ * kInv

	x := ModMul(sigma, kInv) // x = σ * kInv = (k*x) / k = x
	innerSum := ModAdd(messageHash, ModMul(r, x))
	s := ModMul(kInv, innerSum)

	// Distribute s as partial signatures (in simulation, equal distribution)
	n := len(allRound1)
	partialS := ModMul(s, ModInverse(big.NewInt(int64(n))))

	return &SignRound3Output{
		PartyIndex:  partyIndex,
		PartialSigS: partialS,
	}, R, nil
}

// CombineSignatures combines partial signatures to produce final signature
func CombineSignatures(allRound3 []*SignRound3Output, R *Point) (*Signature, error) {
	if len(allRound3) == 0 {
		return nil, fmt.Errorf("no partial signatures")
	}

	r := new(big.Int).Mod(R.X, N)

	// s = Σ s_i
	s := big.NewInt(0)
	for _, r3 := range allRound3 {
		s = ModAdd(s, r3.PartialSigS)
	}

	// Normalize s to lower half of curve order (malleability protection)
	halfN := new(big.Int).Rsh(N, 1)
	v := 0
	if s.Cmp(halfN) > 0 {
		s = ModSub(N, s)
		v = 1
	}

	return &Signature{
		R: r,
		S: s,
		V: v,
	}, nil
}

// RunThresholdSign executes the complete threshold signing protocol
func RunThresholdSign(message []byte, ctx *KeyGenContext, participants []int) (*Signature, error) {
	signCtx, err := NewSignContext(message, participants, ctx)
	if err != nil {
		return nil, err
	}

	// Round 1: Generate nonce shares and commitments
	round1Outputs := make([]*SignRound1Output, len(participants))
	for i, idx := range participants {
		output, err := SignRound1(idx)
		if err != nil {
			return nil, fmt.Errorf("party %d round 1 failed: %w", idx, err)
		}
		round1Outputs[i] = output
	}

	// Round 2: Compute MtA shares for k*γ and k*x
	round2Outputs := make([]*SignRound2Output, len(participants))
	for i, idx := range participants {
		output, err := SignRound2(idx, round1Outputs[i], round1Outputs, signCtx.Parties[idx].SecretShare)
		if err != nil {
			return nil, fmt.Errorf("party %d round 2 failed: %w", idx, err)
		}
		round2Outputs[i] = output
	}

	// Round 3: Compute partial signatures
	round3Outputs := make([]*SignRound3Output, len(participants))
	var R *Point
	for i := range participants {
		output, RPoint, err := SignRound3(
			round1Outputs[i].PartyIndex,
			round1Outputs[i],
			round1Outputs,
			round2Outputs[i],
			round2Outputs,
			signCtx.MessageHash,
		)
		if err != nil {
			return nil, fmt.Errorf("party %d round 3 failed: %w", round1Outputs[i].PartyIndex, err)
		}
		round3Outputs[i] = output
		R = RPoint
	}

	// Combine partial signatures
	sig, err := CombineSignatures(round3Outputs, R)
	if err != nil {
		return nil, fmt.Errorf("failed to combine signatures: %w", err)
	}

	return sig, nil
}

// VerifySignature verifies an ECDSA signature using standard verification
func VerifySignature(message []byte, sig *Signature, publicKey *Point) bool {
	if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return false
	}
	if sig.R.Cmp(N) >= 0 || sig.S.Cmp(N) >= 0 {
		return false
	}

	messageHash := HashToScalar(message)
	sInv := ModInverse(sig.S)

	// u1 = m * s^{-1} mod n
	u1 := ModMul(messageHash, sInv)

	// u2 = r * s^{-1} mod n
	u2 := ModMul(sig.R, sInv)

	// P = u1*G + u2*PublicKey
	u1G := ScalarBaseMult(u1)
	u2Pub := publicKey.ScalarMult(u2)
	P := u1G.Add(u2Pub)

	// Verify: r == P.x mod n
	recoveredR := new(big.Int).Mod(P.X, N)
	return recoveredR.Cmp(sig.R) == 0
}

// ToECDSAPublicKey converts Point to standard ecdsa.PublicKey
func (p *Point) ToECDSAPublicKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: Curve,
		X:     p.X,
		Y:     p.Y,
	}
}
