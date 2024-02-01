package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseCommittee(t *testing.T) {
	d, err := os.ReadFile("./fixtures/beacon_states_8165556_committees.json")

	assert.Nil(t, err)

	resp := CommitteeResponse{}
	err = json.Unmarshal(d, &resp)

	assert.Nil(t, err)

	assert.False(t, resp.ExecutionOptimistic)
	assert.False(t, resp.Finalized)

	committee, err := resp.FindCommittee(8165536, 18)

	assert.Nil(t, err)

	assert.Equal(t, Index(18), committee.Index)
	assert.Equal(t, Slot(8165536), committee.Slot)
	assert.Equal(t, "982483", committee.Validators[0])
}

func TestParseAttestationData(t *testing.T) {
	fixture := `
	{
		"slot": "8165555",
		"index": "1",
		"beacon_block_root": "0xfec8b4772b0d37f873bc01e74944b92a4c3918e5624391fb2aa229cedf9fac54",
		"source": {
			"epoch": "255172",
			"root": "0xf0463186e051a4e04b0172d73237b94c85dcfbbd0038fd1f135fc48e14361bdd"
		},
		"target": {
			"epoch": "255173",
			"root": "0x37e7914708c50792554195b4e41e2ba1b0a19d1578138364b9584b97c299d663"
		}
	}
	`

	attestationData := AttestationData{}

	err := json.Unmarshal([]byte(fixture), &attestationData)

	assert.Nil(t, err)
	assert.Equal(t, Slot(8165555), attestationData.Slot)
}
