package gg20

import (
	"math/big"
)

// Polynomial represents a polynomial over a finite field
type Polynomial struct {
	Coeffs []*big.Int // coeffs[0] is the constant term
}

// NewPolynomial creates a new polynomial with given coefficients
func NewPolynomial(coeffs []*big.Int) *Polynomial {
	p := &Polynomial{
		Coeffs: make([]*big.Int, len(coeffs)),
	}
	for i, c := range coeffs {
		p.Coeffs[i] = new(big.Int).Set(c)
	}
	return p
}

// RandomPolynomial creates a random polynomial of given degree with specified constant term
func RandomPolynomial(degree int, constantTerm *big.Int) (*Polynomial, error) {
	coeffs := make([]*big.Int, degree+1)
	coeffs[0] = new(big.Int).Set(constantTerm)

	for i := 1; i <= degree; i++ {
		coeff, err := RandomScalar()
		if err != nil {
			return nil, err
		}
		coeffs[i] = coeff
	}

	return NewPolynomial(coeffs), nil
}

// ZeroPolynomial creates a polynomial that evaluates to zero at x=0
func ZeroPolynomial(degree int) (*Polynomial, error) {
	return RandomPolynomial(degree, big.NewInt(0))
}

// Eval evaluates the polynomial at point x using Horner's method
func (p *Polynomial) Eval(x *big.Int) *big.Int {
	if len(p.Coeffs) == 0 {
		return big.NewInt(0)
	}

	result := new(big.Int).Set(p.Coeffs[len(p.Coeffs)-1])
	for i := len(p.Coeffs) - 2; i >= 0; i-- {
		result = ModMul(result, x)
		result = ModAdd(result, p.Coeffs[i])
	}
	return result
}

// Degree returns the degree of the polynomial
func (p *Polynomial) Degree() int {
	return len(p.Coeffs) - 1
}

// Add adds two polynomials
func (p *Polynomial) Add(q *Polynomial) *Polynomial {
	maxLen := len(p.Coeffs)
	if len(q.Coeffs) > maxLen {
		maxLen = len(q.Coeffs)
	}

	coeffs := make([]*big.Int, maxLen)
	for i := 0; i < maxLen; i++ {
		coeffs[i] = big.NewInt(0)
		if i < len(p.Coeffs) {
			coeffs[i] = ModAdd(coeffs[i], p.Coeffs[i])
		}
		if i < len(q.Coeffs) {
			coeffs[i] = ModAdd(coeffs[i], q.Coeffs[i])
		}
	}
	return NewPolynomial(coeffs)
}

// CommitmentPolynomial creates commitments to polynomial coefficients: A_i = g^{a_i}
func (p *Polynomial) CommitmentPolynomial() []*Point {
	commitments := make([]*Point, len(p.Coeffs))
	for i, coeff := range p.Coeffs {
		commitments[i] = ScalarBaseMult(coeff)
	}
	return commitments
}

// VerifyShare verifies a share against polynomial commitments using Feldman VSS
// Checks: g^{share} == prod_{j=0}^{t} (A_j)^{i^j}
func VerifyShare(partyIndex int, share *big.Int, commitments []*Point) bool {
	// Left side: g^{share}
	lhs := ScalarBaseMult(share)

	// Right side: prod_{j=0}^{t} (A_j)^{i^j}
	idx := big.NewInt(int64(partyIndex))
	rhs := &Point{X: big.NewInt(0), Y: big.NewInt(0)}

	idxPow := big.NewInt(1)
	for j := 0; j < len(commitments); j++ {
		// A_j ^ (i^j)
		term := commitments[j].ScalarMult(idxPow)

		if rhs.IsIdentity() {
			rhs = term
		} else {
			rhs = rhs.Add(term)
		}

		idxPow = ModMul(idxPow, idx)
	}

	return lhs.Equal(rhs)
}

// LagrangeCoefficient computes the Lagrange coefficient for party i at x=0
// λ_i = prod_{j!=i} (0 - j) / (i - j) = prod_{j!=i} j / (j - i)
func LagrangeCoefficient(partyIndex int, parties []int) *big.Int {
	i := big.NewInt(int64(partyIndex))
	numerator := big.NewInt(1)
	denominator := big.NewInt(1)

	for _, j := range parties {
		if j == partyIndex {
			continue
		}
		jBig := big.NewInt(int64(j))

		// numerator *= j (evaluating at x=0, so (0-j) = -j, but we use j and adjust sign)
		numerator = ModMul(numerator, jBig)

		// denominator *= (j - i)
		diff := ModSub(jBig, i)
		denominator = ModMul(denominator, diff)
	}

	// λ = numerator / denominator mod N
	return ModMul(numerator, ModInverse(denominator))
}

// InterpolateSecret reconstructs the secret from shares using Lagrange interpolation
func InterpolateSecret(shares map[int]*big.Int) *big.Int {
	parties := make([]int, 0, len(shares))
	for idx := range shares {
		parties = append(parties, idx)
	}

	secret := big.NewInt(0)
	for idx, share := range shares {
		lambda := LagrangeCoefficient(idx, parties)
		term := ModMul(lambda, share)
		secret = ModAdd(secret, term)
	}

	return secret
}
