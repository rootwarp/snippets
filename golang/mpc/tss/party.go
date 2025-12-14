package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/tss"
)

// LocalParty represents a party in the MPC protocol
type LocalParty struct {
	ID        *tss.PartyID
	Params    *tss.Parameters
	OutCh     chan tss.Message
	EndCh     interface{}
	ErrCh     chan *tss.Error
	Key       interface{}
	SavedData interface{}
}

// PartyConfig holds configuration for party setup
type PartyConfig struct {
	PartyCount int
	Threshold  int
}

// DefaultConfig returns default configuration for 3 parties with threshold 2
func DefaultConfig() *PartyConfig {
	return &PartyConfig{
		PartyCount: 3,
		Threshold:  1, // t+1 = 2 parties needed to sign (threshold is t, so we need t+1)
	}
}

// GeneratePartyIDs creates party IDs for all participants
func GeneratePartyIDs(count int) tss.SortedPartyIDs {
	partyIDs := make([]*tss.PartyID, count)
	for i := 0; i < count; i++ {
		key := new(big.Int).SetInt64(int64(i + 1))
		partyIDs[i] = tss.NewPartyID(
			fmt.Sprintf("party-%d", i+1),
			fmt.Sprintf("Party %d", i+1),
			key,
		)
	}
	return tss.SortPartyIDs(partyIDs)
}

// GeneratePreParams generates pre-parameters for a party (expensive operation)
// In production, these should be pre-computed and stored
func GeneratePreParams() (*big.Int, error) {
	// This is a simplified version - in real implementation,
	// tss-lib provides LocalPreParams generation
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 256))
}

// parseMessage parses a tss.Message into a tss.ParsedMessage for a specific party
func parseMessage(msg tss.Message, party tss.Party) (tss.ParsedMessage, error) {
	wireBytes, _, err := msg.WireBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get wire bytes: %v", err)
	}
	
	from := msg.GetFrom()
	isBroadcast := msg.IsBroadcast()
	
	parsedMsg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return nil, fmt.Errorf("failed to parse wire message: %v", err)
	}
	
	return parsedMsg, nil
}

// updatePartyWithMessage updates a party with a message, handling serialization/deserialization
func updatePartyWithMessage(party tss.Party, msg tss.Message) error {
	parsedMsg, err := parseMessage(msg, party)
	if err != nil {
		return err
	}
	
	_, err = party.Update(parsedMsg)
	return err
}
