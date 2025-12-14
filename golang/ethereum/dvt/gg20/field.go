package gg20

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// Secp256k1 curve parameters
var (
	Curve = elliptic.P256() // Using P256 for simplicity (production should use secp256k1)
	N     = Curve.Params().N // Order of the curve
	G     = struct{ X, Y *big.Int }{
		X: Curve.Params().Gx,
		Y: Curve.Params().Gy,
	}
)

// Point represents a point on the elliptic curve
type Point struct {
	X, Y *big.Int
}

// NewPoint creates a new point
func NewPoint(x, y *big.Int) *Point {
	return &Point{X: new(big.Int).Set(x), Y: new(big.Int).Set(y)}
}

// ScalarBaseMult multiplies the base point G by scalar
func ScalarBaseMult(scalar *big.Int) *Point {
	x, y := Curve.ScalarBaseMult(scalar.Bytes())
	return &Point{X: x, Y: y}
}

// ScalarMult multiplies a point by scalar
func (p *Point) ScalarMult(scalar *big.Int) *Point {
	x, y := Curve.ScalarMult(p.X, p.Y, scalar.Bytes())
	return &Point{X: x, Y: y}
}

// Add adds two points
func (p *Point) Add(q *Point) *Point {
	x, y := Curve.Add(p.X, p.Y, q.X, q.Y)
	return &Point{X: x, Y: y}
}

// Equal checks if two points are equal
func (p *Point) Equal(q *Point) bool {
	return p.X.Cmp(q.X) == 0 && p.Y.Cmp(q.Y) == 0
}

// IsIdentity checks if point is the identity (point at infinity)
func (p *Point) IsIdentity() bool {
	return p.X.Sign() == 0 && p.Y.Sign() == 0
}

// RandomScalar generates a random scalar in [1, N-1]
func RandomScalar() (*big.Int, error) {
	for {
		k, err := rand.Int(rand.Reader, N)
		if err != nil {
			return nil, err
		}
		if k.Sign() > 0 {
			return k, nil
		}
	}
}

// ModAdd performs modular addition: (a + b) mod N
func ModAdd(a, b *big.Int) *big.Int {
	result := new(big.Int).Add(a, b)
	return result.Mod(result, N)
}

// ModSub performs modular subtraction: (a - b) mod N
func ModSub(a, b *big.Int) *big.Int {
	result := new(big.Int).Sub(a, b)
	return result.Mod(result, N)
}

// ModMul performs modular multiplication: (a * b) mod N
func ModMul(a, b *big.Int) *big.Int {
	result := new(big.Int).Mul(a, b)
	return result.Mod(result, N)
}

// ModInverse computes the modular inverse: a^(-1) mod N
func ModInverse(a *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, N)
}

// ModNeg computes the negation: -a mod N
func ModNeg(a *big.Int) *big.Int {
	result := new(big.Int).Neg(a)
	return result.Mod(result, N)
}

// HashToScalar hashes arbitrary data to a scalar
func HashToScalar(data ...[]byte) *big.Int {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	hash := h.Sum(nil)
	result := new(big.Int).SetBytes(hash)
	return result.Mod(result, N)
}

// Commitment represents a Pedersen commitment
type Commitment struct {
	C *Point
}

// PedersenCommit creates a Pedersen commitment: C = g^v * h^r
func PedersenCommit(value, randomness *big.Int, h *Point) *Commitment {
	gv := ScalarBaseMult(value)
	hr := h.ScalarMult(randomness)
	return &Commitment{C: gv.Add(hr)}
}
