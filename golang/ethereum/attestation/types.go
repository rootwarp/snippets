package main

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/ferranbt/fastssz"
)

var (
	DOMAIN_TYPE_ATTESTER = []byte{0x01, 0x00, 0x00, 0x00}
	CAPELLA_FORK_VERSION = Version([]byte{0x03, 0x00, 0x00, 0x00})
)

type (
	Slot    uint64
	Index   uint64
	Epoch   uint64
	Hash    [32]byte
	Version [4]byte
	AggBit  string
)

func (c *Slot) UnmarshalJSON(data []byte) error {
	no, err := strconv.ParseUint(strings.Trim(string(data), "\""), 10, 64)
	if err != nil {
		return err
	}

	*c = Slot(no)

	return nil
}

func (i *Index) UnmarshalJSON(data []byte) error {
	no, err := strconv.ParseUint(strings.Trim(string(data), "\""), 10, 64)
	if err != nil {
		return err
	}

	*i = Index(no)

	return nil
}

func (i *Epoch) UnmarshalJSON(data []byte) error {
	no, err := strconv.ParseUint(strings.Trim(string(data), "\""), 10, 64)
	if err != nil {
		return err
	}

	*i = Epoch(no)

	return nil
}

func (h *Hash) UnmarshalJSON(data []byte) error {
	raw := strings.Trim(string(data), "\"")
	hash, err := hex.DecodeString(strings.TrimLeft(raw, "0x"))
	if err != nil {
		return err
	}

	*h = Hash(hash)

	return nil
}

func (a AggBit) String() string {
	return string(a)
}

func (a AggBit) ToIndex() []int {
	idx := 0
	valIndex := []int{}
	aggBitsStr := strings.TrimPrefix(a.String(), "0x")
	for i := 0; i < len(aggBitsStr); i += 2 {
		split := aggBitsStr[i : i+2]
		intVal, err := strconv.ParseUint(split, 16, 64)
		if err != nil {
			panic(err)
		}

		bitmask := uint64(1)
		for j := 0; j < 8; j++ {
			if intVal&bitmask > 0 {
				valIndex = append(valIndex, idx)
			}

			bitmask = bitmask << 1
			idx += 1
		}
	}

	return valIndex
}

type CommitteeResponse struct {
	ExecutionOptimistic bool        `json:"execution_optimistic"`
	Finalized           bool        `json:"finalized"`
	Data                []Committee `json:"data"`
}

func (r *CommitteeResponse) FindCommittee(slot Slot, index Index) (*Committee, error) {
	for _, committee := range r.Data {
		if committee.Slot == slot && committee.Index == index {
			return &committee, nil
		}
	}
	return nil, fmt.Errorf("cannot found committee %d, %d", slot, index)
}

type Committee struct {
	Index      Index    `json:"index"`
	Slot       Slot     `json:"slot"`
	Validators []string `json:"validators"`
}

// -----

type Block struct {
	Version             string `json:"version"`
	ExecutionOptimistic bool   `json:"execution_optimistic"`
	Finalized           bool   `json:"finalized"`
	Data                Data   `json:"data"`
	Signature           string `json:"signature"`
}

type Data struct {
	Message   Message `json:"message"`
	Signature string  `json:"signature"`
}

type Message struct {
	Slot          Slot   `json:"slot"`
	ProposerIndex string `json:"proposer_index"`
	ParentRoot    Hash   `json:"parent_root"`
	StateRoot     Hash   `json:"state_root"`
	Body          Body   `json:"body"`
}

type Body struct {
	RandaoReveal string `json:"randao_reveal"`
	// Eth1Data          Eth1Data           `json:"eth1_data"`
	Graffiti string `json:"graffiti"`
	// ProposerSlashings []ProposerSlashing `json:"proposer_slashings"`
	// AttesterSlashings []AttesterSlashing `json:"attester_slashings"`
	Attestations []Attestation `json:"attestations"`
	// Deposits          []Deposit          `json:"deposits"`
	// VoluntaryExits    []VoluntaryExit    `json:"voluntary_exits"`
}

func (b Body) FindAttestationByIndex(idx Index) []Attestation {
	filtered := make([]Attestation, 0)
	for _, att := range b.Attestations {
		if att.Data.Index == idx {
			filtered = append(filtered, att)
		}
	}

	return filtered
}

type Attestation struct {
	AggregationBits AggBit          `json:"aggregation_bits"`
	Signature       string          `json:"signature"`
	Data            AttestationData `json:"data"`
}

type AttestationData struct {
	Slot            Slot        `json:"slot"`
	Index           Index       `json:"index"`
	BeaconBlockHash Hash        `json:"beacon_block_root" ssz-size:"32"`
	Source          *Checkpoint `json:"source"`
	Target          *Checkpoint `json:"target"`
}

type Checkpoint struct {
	Epoch Epoch `json:"epoch"`
	Root  Hash  `json:"root"  ssz-size:"32"`
}

func (c *Checkpoint) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(c)
}

// MarshalSSZTo ssz marshals the Checkpoint object to a target array
func (c *Checkpoint) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	// Field (0) 'Epoch'
	dst = ssz.MarshalUint64(dst, uint64(c.Epoch))

	// Field (1) 'Root'
	if size := len(c.Root); size != 32 {
		err = ssz.ErrBytesLengthFn("Checkpoint.Root", size, 32)
		return
	}
	dst = append(dst, c.Root[:]...)

	return
}

// UnmarshalSSZ ssz unmarshals the Checkpoint object
func (c *Checkpoint) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size != 40 {
		return ssz.ErrSize
	}

	// Field (0) 'Epoch'
	c.Epoch = Epoch(ssz.UnmarshallUint64(buf[0:8]))

	// Field (1) 'Root'
	var h []byte
	if cap(c.Root) == 0 {
		// c.Root = make([]byte, 0, len(buf[8:40]))
		h = make([]byte, 0, len(buf[8:40]))
	}
	// c.Root = append(c.Root[:], buf[8:40]...)
	h = append(h, buf[8:40]...)

	copy(c.Root[:], h)

	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the Checkpoint object
func (c *Checkpoint) SizeSSZ() (size int) {
	size = 40
	return
}

// HashTreeRoot ssz hashes the Checkpoint object
func (c *Checkpoint) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(c)
}

// HashTreeRootWith ssz hashes the Checkpoint object with a hasher
func (c *Checkpoint) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Epoch'
	hh.PutUint64(uint64(c.Epoch))

	// Field (1) 'Root'
	if size := len(c.Root); size != 32 {
		err = ssz.ErrBytesLengthFn("Checkpoint.Root", size, 32)
		return
	}
	hh.PutBytes(c.Root[:])

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the Checkpoint object
func (c *Checkpoint) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(c)
}

// MarshalSSZ ssz marshals the AttestationData object
func (a *AttestationData) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(a)
}

// MarshalSSZTo ssz marshals the AttestationData object to a target array
func (a *AttestationData) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	// Field (0) 'Slot'
	dst = ssz.MarshalUint64(dst, uint64(a.Slot))

	// Field (1) 'Index'
	dst = ssz.MarshalUint64(dst, uint64(a.Index))

	// Field (2) 'BeaconBlockHash'
	dst = append(dst, a.BeaconBlockHash[:]...)

	// Field (3) 'Source'
	if a.Source == nil {
		a.Source = new(Checkpoint)
	}
	if dst, err = a.Source.MarshalSSZTo(dst); err != nil {
		return
	}

	// Field (4) 'Target'
	if a.Target == nil {
		a.Target = new(Checkpoint)
	}
	if dst, err = a.Target.MarshalSSZTo(dst); err != nil {
		return
	}

	return
}

// UnmarshalSSZ ssz unmarshals the AttestationData object
func (a *AttestationData) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size != 128 {
		return ssz.ErrSize
	}

	// Field (0) 'Slot'
	a.Slot = Slot(ssz.UnmarshallUint64(buf[0:8]))

	// Field (1) 'Index'
	a.Index = Index(ssz.UnmarshallUint64(buf[8:16]))

	// Field (2) 'BeaconBlockHash'
	copy(a.BeaconBlockHash[:], buf[16:48])

	// Field (3) 'Source'
	if a.Source == nil {
		a.Source = new(Checkpoint)
	}
	if err = a.Source.UnmarshalSSZ(buf[48:88]); err != nil {
		return err
	}

	// Field (4) 'Target'
	if a.Target == nil {
		a.Target = new(Checkpoint)
	}
	if err = a.Target.UnmarshalSSZ(buf[88:128]); err != nil {
		return err
	}

	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the AttestationData object
func (a *AttestationData) SizeSSZ() (size int) {
	size = 128
	return
}

// HashTreeRoot ssz hashes the AttestationData object
func (a *AttestationData) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(a)
}

// HashTreeRootWith ssz hashes the AttestationData object with a hasher
func (a *AttestationData) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Slot'
	hh.PutUint64(uint64(a.Slot))

	// Field (1) 'Index'
	hh.PutUint64(uint64(a.Index))

	// Field (2) 'BeaconBlockHash'
	hh.PutBytes(a.BeaconBlockHash[:])

	// Field (3) 'Source'
	if a.Source == nil {
		a.Source = new(Checkpoint)
	}
	if err = a.Source.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (4) 'Target'
	if a.Target == nil {
		a.Target = new(Checkpoint)
	}
	if err = a.Target.HashTreeRootWith(hh); err != nil {
		return
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the AttestationData object
func (a *AttestationData) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(a)
}

type ValidatorResponse struct {
	ExecutionOptimistic bool          `json:"execution_optimistic"`
	Finalized           bool          `json:"finalized"`
	Data                ValidatorData `json:"data"`
}

type ValidatorData struct {
	Index     Index     `json:"index"`
	Balance   string    `json:"balance"`
	Status    string    `json:"status"`
	Validator Validator `json:"validator"`
}

type Validator struct {
	Pubkey                     string `json:"pubkey"`
	WithdrawalCredentials      string `json:"withdrawal_credentials"`
	EffectiveBalance           string `json:"effective_balance"`
	Slashed                    bool   `json:"slashed"`
	ActivationEligibilityEpoch Epoch  `json:"activation_eligibility_epoch"`
	ActivationEpoch            Epoch  `json:"activation_epoch"`
	ExitEpoch                  Epoch  `json:"exit_epoch"`
	WithdrawableEpoch          Epoch  `json:"withdrawable_epoch"`
}

type ForkData struct {
	CurrentVersion        Version `json:"current_version"`
	GenesisValidatorsRoot Hash    `json:"genesis_validators_root"`
}

func (f *ForkData) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(f)
}

func (f *ForkData) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	// dst = ssz.MarshalUint32(dst, uint32(f.CurrentVersion))
	dst = append(dst, f.CurrentVersion[:]...)
	dst = append(dst, f.GenesisValidatorsRoot[:]...)
	return
}

func (f *ForkData) SizeSSZ() int {
	return (4 + 32)
}

func (f *ForkData) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(f)
}

func (f *ForkData) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(f)
}

func (f *ForkData) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	hh.PutBytes(f.CurrentVersion[:])
	hh.PutBytes(f.GenesisValidatorsRoot[:])

	hh.Merkleize(indx)
	return nil
}

type SigningData struct {
	ObjectRoot Hash `json:"object_root"`
	Domain     Hash `json:"domain"`
}

func (f *SigningData) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(f)
}

func (f *SigningData) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	// dst = ssz.MarshalUint32(dst, uint32(f.CurrentVersion))
	dst = append(dst, f.ObjectRoot[:]...)
	dst = append(dst, f.Domain[:]...)
	return
}

func (f *SigningData) SizeSSZ() int {
	return (4 + 32)
}

func (f *SigningData) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(f)
}

func (f *SigningData) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(f)
}

func (f *SigningData) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	hh.PutBytes(f.ObjectRoot[:])
	hh.PutBytes(f.Domain[:])

	hh.Merkleize(indx)
	return nil
}
