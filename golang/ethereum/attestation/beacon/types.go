package beacon

import "strconv"

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
	Slot          string `json:"slot"`
	ProposerIndex string `json:"proposer_index"`
	ParentRoot    string `json:"parent_root"`
	StateRoot     string `json:"state_root"`
	Body          Body   `json:"body"`
}

type Body struct {
	RandaoReveal      string             `json:"randao_reveal"`
	Eth1Data          Eth1Data           `json:"eth1_data"`
	Graffiti          string             `json:"graffiti"`
	ProposerSlashings []ProposerSlashing `json:"proposer_slashings"`
	AttesterSlashings []AttesterSlashing `json:"attester_slashings"`
	Attestations      []Attestation      `json:"attestations"`
	Deposits          []Deposit          `json:"deposits"`
	VoluntaryExits    []VoluntaryExit    `json:"voluntary_exits"`
}

type Eth1Data struct {
	DepositRoot  string `json:"deposit_root"`
	DepositCount string `json:"deposit_count"`
	BlockHash    string `json:"block_hash"`
}

type ProposerSlashing struct {
	SignedHeader1 SignedHeader `json:"signed_header_1"`
	SignedHeader2 SignedHeader `json:"signed_header_2"`
}

type SignedHeader struct {
	Message   HeaderMessage `json:"message"`
	Signature string        `json:"signature"`
}

type HeaderMessage struct {
	Slot          string `json:"slot"`
	ProposerIndex string `json:"proposer_index"`
	ParentRoot    string `json:"parent_root"`
	StateRoot     string `json:"state_root"`
	BodyRoot      string `json:"body_root"`
}

type AttesterSlashing struct {
	Attestation1 AttestationData `json:"attestation_1"`
	Attestation2 AttestationData `json:"attestation_2"`
}

type AttestationData struct {
	AttestingIndices []string    `json:"attesting_indices"`
	Signature        string      `json:"signature"`
	Data             Attestation `json:"data"`
}

type Attestation struct {
	Slot            string     `json:"slot"`
	Index           string     `json:"index"`
	BeaconBlockRoot string     `json:"beacon_block_root"`
	Source          Checkpoint `json:"source"`
	Target          Checkpoint `json:"target"`
}

type Attestations []Attestation

func (a Attestations) FindByIndex(no int) Attestations {
	filtered := make([]Attestation, 0)

	for _, attestation := range a {
		if attestation.Index == strconv.Itoa(no) {
			filtered = append(filtered, attestation)
		}
	}

	return filtered
}

type Checkpoint struct {
	Epoch string `json:"epoch"`
	Root  string `json:"root"`
}

type Deposit struct {
	Proof []string    `json:"proof"`
	Data  DepositData `json:"data"`
}

type DepositData struct {
	Pubkey                string `json:"pubkey"`
	WithdrawalCredentials string `json:"withdrawal_credentials"`
	Amount                string `json:"amount"`
	Signature             string `json:"signature"`
}

type VoluntaryExit struct {
	Message   ExitMessage `json:"message"`
	Signature string      `json:"signature"`
}

type ExitMessage struct {
	Epoch          string `json:"epoch"`
	ValidatorIndex string `json:"validator_index"`
}
