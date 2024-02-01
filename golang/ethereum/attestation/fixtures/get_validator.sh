#!/bin/bash

SLOT=$1
VALIDATOR_INDEX=$2

FILENAME=beacon_states_${SLOT}_validators_${VALIDATOR_INDEX}.json

curl https://cl.eth.rootwarp.dev/eth/v1/beacon/states/$SLOT/validators/$VALIDATOR_INDEX | jq . > $FILENAME
