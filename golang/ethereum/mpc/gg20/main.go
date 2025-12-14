package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/bnb-chain/tss-lib/common"
	tsscrypto "github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/resharing"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
	"github.com/btcsuite/btcd/btcec/v2"
)

func main() {
	log.SetFlags(0)

	curve := tss.S256() // secp256k1
	threshold := 1      // t=1 => 2-of-3

	// --- GG20 keygen for 3 parties ---
	oldParties := mustPartyIDs([]string{"P1", "P2", "P3"}, 0)
	oldSaves := mustRunKeygen(curve, oldParties, threshold)

	pub := mustECDSAPubkey(curve, oldSaves[oldParties[0].Id])
	log.Printf("Keygen complete. Group pubkey X=%x Y=%x", pad32(pub.X().Bytes()), pad32(pub.Y().Bytes()))

	// --- Threshold signature (2-of-3) ---
	msg := []byte("hello gg20")
	h := sha256.Sum256(msg)
	msgHash := h[:]
	// NOTE: do not re-sort `oldParties` pointers (SortPartyIDs mutates Index); clone first.
	signingParties := cloneAndSortPartyIDs([]*tss.PartyID{oldParties[0], oldParties[1]})
	sig1 := mustRunSigning(curve, signingParties, threshold, oldSaves, msgHash)
	log.Printf("Signature1 (r||s): %s", hex.EncodeToString(sig1))
	mustVerifySig(pub, msgHash, sig1)
	log.Printf("Signature1 verified")

	// --- Resharing: old committee (P1,P2,P3) -> new committee (Q1,Q2,Q3) ---
	newParties := mustPartyIDs([]string{"Q1", "Q2", "Q3"}, 100) // ensure unique keys vs old committee
	newSaves := mustRunResharing(curve, oldParties, newParties, threshold, threshold, oldSaves)

	newPub := mustECDSAPubkey(curve, newSaves[newParties[0].Id])
	if pub.X().Cmp(newPub.X()) != 0 || pub.Y().Cmp(newPub.Y()) != 0 {
		log.Fatalf("resharing changed public key (unexpected)")
	}
	log.Printf("Resharing complete. Public key preserved.")

	// --- Sign again with reshared shares ---
	msg2 := []byte("hello gg20 after resharing")
	h2 := sha256.Sum256(msg2)
	msgHash2 := h2[:]
	newSigningParties := cloneAndSortPartyIDs([]*tss.PartyID{newParties[1], newParties[2]})
	sig2 := mustRunSigning(curve, newSigningParties, threshold, newSaves, msgHash2)
	log.Printf("Signature2 (r||s): %s", hex.EncodeToString(sig2))
	mustVerifySig(newPub, msgHash2, sig2)
	log.Printf("Signature2 verified")
}

func mustPartyIDs(names []string, startAt int) tss.SortedPartyIDs {
	ids := make([]*tss.PartyID, 0, len(names))
	for i, n := range names {
		ids = append(ids, tss.NewPartyID(n, n, big.NewInt(int64(startAt+i+1))))
	}
	// PartyID.Index must be 0..(n-1) within each committee; `startAt` is only for distinct keys.
	return tss.SortPartyIDs(ids)
}

func cloneAndSortPartyIDs(ids []*tss.PartyID) tss.SortedPartyIDs {
	clones := make([]*tss.PartyID, 0, len(ids))
	for _, id := range ids {
		clones = append(clones, tss.NewPartyID(id.Id, id.Moniker, id.KeyInt()))
	}
	return tss.SortPartyIDs(clones)
}

func mustECDSAPubkey(curve elliptic.Curve, save keygen.LocalPartySaveData) *tsscrypto.ECPoint {
	if save.ECDSAPub == nil {
		log.Fatalf("missing ECDSA pubkey in save data")
	}
	if !curve.IsOnCurve(save.ECDSAPub.X(), save.ECDSAPub.Y()) {
		log.Fatalf("saved pubkey not on curve")
	}
	return save.ECDSAPub
}

func mustVerifySig(pub *tsscrypto.ECPoint, msgHash []byte, sigRS []byte) {
	if len(sigRS) != 64 {
		log.Fatalf("expected 64-byte (r||s) signature, got %d", len(sigRS))
	}
	r := new(big.Int).SetBytes(sigRS[:32])
	s := new(big.Int).SetBytes(sigRS[32:])

	pk := ecdsa.PublicKey{Curve: btcec.S256(), X: pub.X(), Y: pub.Y()}
	if !ecdsa.Verify(&pk, msgHash, r, s) {
		log.Fatalf("ecdsa verification failed")
	}
}

func mustRunKeygen(curve elliptic.Curve, partyIDs tss.SortedPartyIDs, threshold int) map[string]keygen.LocalPartySaveData {
	peerCtx := tss.NewPeerContext(partyIDs)

	// Pre-generate pre-params in parallel (this is expensive; in real systems you should do it out-of-band).
	preParams := make(map[string]keygen.LocalPreParams, len(partyIDs))
	{
		var mu sync.Mutex
		var wg sync.WaitGroup
		errCh := make(chan error, len(partyIDs))
		for _, id := range partyIDs {
			id := id
			wg.Add(1)
			go func() {
				defer wg.Done()
				pp, err := keygen.GeneratePreParams(10 * time.Minute)
				if err != nil {
					errCh <- err
					return
				}
				mu.Lock()
				preParams[id.Id] = *pp
				mu.Unlock()
			}()
		}
		wg.Wait()
		close(errCh)
		if err := <-errCh; err != nil {
			log.Fatalf("pre-params generation failed: %v", err)
		}
	}

	r := newRouter(nil, nil)

	endCh := make(chan keygen.LocalPartySaveData, len(partyIDs))
	errCh := make(chan *tss.Error, len(partyIDs))

	parties := make([]tss.Party, 0, len(partyIDs))
	for _, id := range partyIDs {
		params := tss.NewParameters(curve, peerCtx, id, len(partyIDs), threshold)
		outCh := make(chan tss.Message, 1024)
		p := keygen.NewLocalParty(params, outCh, endCh, preParams[id.Id])
		parties = append(parties, p)
		r.register(p, outCh)
	}

	var wg sync.WaitGroup
	wg.Add(len(parties))
	for _, p := range parties {
		p := p
		go func() {
			defer wg.Done()
			r.runParty(p, errCh)
		}()
	}
	for _, p := range parties {
		p := p
		go func() {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}()
	}

	// Collect all results and map by ShareID -> PartyID.
	out := make(map[string]keygen.LocalPartySaveData, len(partyIDs))
	deadline := time.NewTimer(15 * time.Minute)
	defer deadline.Stop()
	for len(out) < len(partyIDs) {
		select {
		case save := <-endCh:
			pid := partyIDByShareID(partyIDs, save.ShareID)
			if pid == nil {
				log.Fatalf("keygen produced save data for unknown ShareID %x", save.ShareID.Bytes())
			}
			out[pid.Id] = save
		case err := <-errCh:
			log.Fatalf("keygen error: %v", err)
		case <-deadline.C:
			log.Fatalf("keygen timeout")
		}
	}

	r.stop()
	wg.Wait()
	return out
}

func mustRunSigning(
	curve elliptic.Curve,
	signingParties tss.SortedPartyIDs,
	threshold int,
	saves map[string]keygen.LocalPartySaveData,
	msgHash []byte,
) []byte {
	peerCtx := tss.NewPeerContext(signingParties)
	msgInt := new(big.Int).SetBytes(msgHash)

	r := newRouter(nil, nil)
	endCh := make(chan common.SignatureData, len(signingParties))
	errCh := make(chan *tss.Error, len(signingParties))

	parties := make([]tss.Party, 0, len(signingParties))
	for _, id := range signingParties {
		save, ok := saves[id.Id]
		if !ok {
			log.Fatalf("missing key share for signer %s", id.Id)
		}
		params := tss.NewParameters(curve, peerCtx, id, len(signingParties), threshold)
		outCh := make(chan tss.Message, 1024)
		p := signing.NewLocalParty(msgInt, params, save, outCh, endCh)
		parties = append(parties, p)
		r.register(p, outCh)
	}

	var wg sync.WaitGroup
	wg.Add(len(parties))
	for _, p := range parties {
		p := p
		go func() {
			defer wg.Done()
			r.runParty(p, errCh)
		}()
	}
	for _, p := range parties {
		p := p
		go func() {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}()
	}

	deadline := time.NewTimer(5 * time.Minute)
	defer deadline.Stop()

	// All parties output a signature; accept the first.
	var sigRS []byte
	for sigRS == nil {
		select {
		case sig := <-endCh:
			sigRS = append(pad32(sig.GetR()), pad32(sig.GetS())...)
		case err := <-errCh:
			log.Fatalf("signing error: %v", err)
		case <-deadline.C:
			log.Fatalf("signing timeout")
		}
	}

	r.stop()
	wg.Wait()
	return sigRS
}

func mustRunResharing(
	curve elliptic.Curve,
	oldParties tss.SortedPartyIDs,
	newParties tss.SortedPartyIDs,
	oldThreshold int,
	newThreshold int,
	oldSaves map[string]keygen.LocalPartySaveData,
) map[string]keygen.LocalPartySaveData {
	oldCtx := tss.NewPeerContext(oldParties)
	newCtx := tss.NewPeerContext(newParties)

	union := make([]*tss.PartyID, 0, len(oldParties)+len(newParties))
	union = append(union, oldParties...)
	union = append(union, newParties...)
	// IMPORTANT: don't sort here. SortPartyIDs mutates PartyID.Index and would break old/new committee indices.
	unionIDs := union

	r := newRouter(oldParties, newParties)
	endCh := make(chan keygen.LocalPartySaveData, len(newParties))
	errCh := make(chan *tss.Error, len(unionIDs))

	parties := make([]tss.Party, 0, len(unionIDs))
	for _, id := range unionIDs {
		rp := tss.NewReSharingParameters(curve, oldCtx, newCtx, id, len(oldParties), oldThreshold, len(newParties), newThreshold)
		outCh := make(chan tss.Message, 1024)
		var key keygen.LocalPartySaveData
		if isInCommittee(id, oldParties) {
			key = oldSaves[id.Id]
		}
		p := resharing.NewLocalParty(rp, key, outCh, endCh)
		parties = append(parties, p)
		r.register(p, outCh)
	}

	var wg sync.WaitGroup
	wg.Add(len(parties))
	for _, p := range parties {
		p := p
		go func() {
			defer wg.Done()
			r.runParty(p, errCh)
		}()
	}
	for _, p := range parties {
		p := p
		go func() {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}()
	}

	out := make(map[string]keygen.LocalPartySaveData, len(newParties))
	deadline := time.NewTimer(10 * time.Minute)
	defer deadline.Stop()

	for len(out) < len(newParties) {
		select {
		case save := <-endCh:
			pid := partyIDByShareID(newParties, save.ShareID)
			if pid == nil {
				// some versions may emit save data for old parties too; ignore those
				continue
			}
			out[pid.Id] = save
		case err := <-errCh:
			log.Fatalf("resharing error: %v", err)
		case <-deadline.C:
			log.Fatalf("resharing timeout")
		}
	}

	r.stop()
	wg.Wait()
	return out
}

func partyIDByShareID(ids tss.SortedPartyIDs, shareID *big.Int) *tss.PartyID {
	if shareID == nil {
		return nil
	}
	for _, id := range ids {
		if id.KeyInt().Cmp(shareID) == 0 {
			return id
		}
	}
	return nil
}

func isInCommittee(id *tss.PartyID, committee tss.SortedPartyIDs) bool {
	for _, x := range committee {
		if x.Id == id.Id {
			return true
		}
	}
	return false
}

func pad32(b []byte) []byte {
	if len(b) == 32 {
		return b
	}
	if len(b) > 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// ---- Minimal in-memory message router for tss-lib ----

type router struct {
	mu      sync.RWMutex
	parties map[string]tss.Party
	outChs  map[string]<-chan tss.Message
	stopCh  chan struct{}

	oldSet map[string]bool
	newSet map[string]bool
}

func newRouter(oldCommittee, newCommittee tss.SortedPartyIDs) *router {
	r := &router{
		parties: make(map[string]tss.Party),
		outChs:  make(map[string]<-chan tss.Message),
		stopCh:  make(chan struct{}),
	}
	if oldCommittee != nil {
		r.oldSet = make(map[string]bool, len(oldCommittee))
		for _, id := range oldCommittee {
			r.oldSet[id.Id] = true
		}
	}
	if newCommittee != nil {
		r.newSet = make(map[string]bool, len(newCommittee))
		for _, id := range newCommittee {
			r.newSet[id.Id] = true
		}
	}
	return r
}

func (r *router) register(p tss.Party, out <-chan tss.Message) {
	id := p.PartyID().Id
	r.mu.Lock()
	r.parties[id] = p
	r.outChs[id] = out
	r.mu.Unlock()
}

func (r *router) runParty(p tss.Party, errCh chan<- *tss.Error) {
	id := p.PartyID().Id
	r.mu.RLock()
	out := r.outChs[id]
	r.mu.RUnlock()

	for {
		select {
		case <-r.stopCh:
			return
		case msg := <-out:
			if msg == nil {
				continue
			}
			r.dispatch(msg, errCh)
		}
	}
}

func (r *router) dispatch(msg tss.Message, errCh chan<- *tss.Error) {
	wireBytes, routing, err := msg.WireBytes()
	if err != nil {
		errCh <- tss.NewError(err, "wire", 0, msg.GetFrom())
		return
	}

	fromID := routing.From.Id

	deliver := func(to *tss.PartyID) {
		if to == nil {
			return
		}
		if to.Id == fromID {
			return
		}
		if !r.allowedByCommittee(routing, to.Id) {
			return
		}
		r.mu.RLock()
		p := r.parties[to.Id]
		r.mu.RUnlock()
		if p == nil {
			return
		}
		_, upErr := p.UpdateFromBytes(wireBytes, routing.From, routing.IsBroadcast)
		if upErr != nil {
			errCh <- upErr
		}
	}

	if routing.IsBroadcast || routing.To == nil {
		r.mu.RLock()
		recipients := make([]*tss.PartyID, 0, len(r.parties))
		for id, p := range r.parties {
			if id == fromID {
				continue
			}
			if !r.allowedByCommittee(routing, id) {
				continue
			}
			recipients = append(recipients, p.PartyID())
		}
		r.mu.RUnlock()
		for _, to := range recipients {
			deliver(to)
		}
		return
	}

	for _, to := range routing.To {
		deliver(to)
	}
}

func (r *router) allowedByCommittee(routing *tss.MessageRouting, toID string) bool {
	// Non-resharing flows.
	if r.oldSet == nil && r.newSet == nil {
		return true
	}
	if routing.IsToOldAndNewCommittees {
		return true
	}
	if routing.IsToOldCommittee {
		return r.oldSet[toID]
	}
	// Default for resharing messages is "to new committee".
	return r.newSet[toID]
}

func (r *router) stop() {
	select {
	case <-r.stopCh:
		return
	default:
		close(r.stopCh)
	}
}
