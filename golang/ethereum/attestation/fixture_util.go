package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func fixtureLoadBeaconBlock(no int) (*Block, error) {
	// Retrieved from /eth/v2/beacon/block/{block_id}
	filename := fmt.Sprintf("./fixtures/beacon_blocks_%d.json", no)

	d, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block := Block{}
	err = json.Unmarshal(d, &block)
	if err != nil {
		return nil, err
	}

	return &block, nil
}

func fixtureLoadValidator(slot Slot, index string) (*Validator, error) {
	filename := fmt.Sprintf("./fixtures/beacon_states_%d_validators_%s.json", slot, index)
	d, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	validatorResponse := ValidatorResponse{}
	err = json.Unmarshal(d, &validatorResponse)
	if err != nil {
		return nil, err
	}

	return &validatorResponse.Data.Validator, nil
}

func fixtureLoadCommittee(slot Slot, committeeIndex Index) (*Committee, error) {
	filename := fmt.Sprintf("./fixtures/beacon_states_%d_committees.json", slot)
	d, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	committeeResp := CommitteeResponse{}
	err = json.Unmarshal(d, &committeeResp)
	if err != nil {
		return nil, err
	}

	committee, err := committeeResp.FindCommittee(slot, committeeIndex)

	return committee, nil
}
