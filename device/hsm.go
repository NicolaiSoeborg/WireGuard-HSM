/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/hex"
	"fmt"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

const (
	CURVE25519_OID_RAW = "06032B656E" // 1.3.101.110 ("id-X25519")
)

type DeriveKeyPair struct {
	publicKey  p11.Object
	privateKey p11.Object
}

type Hsm struct {
	session    p11.Session // session object
	privKeyObj p11.Object  // the private key handle key on the hsm
	pubKeyObj  p11.Object  // the public key handle on the hsm
	module     p11.Module
	serialized string
	isReady    bool
}

// Open a session with the HSM, select the slot and login to it
// A public and private key must already exist on the HSM
// The private key must be the Curve25519 Algorithm, OID 1.3.101.110
func InitHsm(modPath string, slot uint, pin string) (*Hsm, error) {
	client := new(Hsm)
	client.isReady = false

	module, err := p11.OpenModule(modPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load module library: %s. Error: %w", modPath, err)
	}
	client.module = module // save so we can close

	slots, err := module.Slots()
	if err != nil {
		return nil, err
	}

	if uint(len(slots)) <= slot {
		return nil, fmt.Errorf("Requested slot (%d) but only %d available", slot, len(slots))
	}

	// try to open a session on the slot
	client.session, err = slots[slot].OpenWriteSession()
	if err != nil {
		return nil, fmt.Errorf("failed to open session on slot %d. Error: %w", slot, err)
	}

	// try to login to the slot

	err = client.session.Login(pin)
	if err != nil {
		return nil, fmt.Errorf("unable to login. error: %w", err)
	}

	// make sure the hsm has a curve25519 key for deriving
	X25519KeyPair, err := client.findDeriveKey()
	if err != nil {
		return nil, fmt.Errorf("failed to find X25519 key for deriving: %w", err)
	}

	client.pubKeyObj = X25519KeyPair.publicKey
	client.privKeyObj = X25519KeyPair.privateKey
	client.serialized = fmt.Sprintf("hsm=%s,%d", modPath, slot)
	client.isReady = true

	return client, nil
}

func (client *Hsm) IsZero() bool {
	return !client.isReady
}

func (client *Hsm) Serialize() string {
	return client.serialized
}

func (client *Hsm) Close() {
	client.session.Logout()
	client.session.Close()
	client.module.Destroy()
}

// Returns a 32 byte length key from the hsm. attempts to convert to a usable WG key
func (client *Hsm) PublicKey() (key NoisePublicKey, err error) {
	var nullKey NoisePublicKey // temp garbage key (all 0's) so we can return the error

	// From my understanding, for X25519 the public key is not stored
	// in `CKA_VALUE` but instead in attribute `CKA_EC_POINT`.
	// "DER-encoding of the public key value in little endian order as defined in RFC 7748"
	// - https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cs01/pkcs11-curr-v3.0-cs01.html
	pubKeyVal, err := client.pubKeyObj.Attribute(pkcs11.CKA_EC_POINT)
	if err != nil {
		return nullKey, err
	}
	if len(pubKeyVal) != NoisePublicKeySize {
		// On a Nitrokey Start, this gets the full EC_POINT value of 34 bytes instead of 32,
		// If prefix is "04 (OCTET STRING) 20 (of length 0x20)" then discard the prefix
		if len(pubKeyVal) == NoisePublicKeySize+2 && pubKeyVal[0] == 0x04 && pubKeyVal[1] == 0x20 {
			pubKeyVal = pubKeyVal[2:]
		} else {
			return nullKey, fmt.Errorf("Key of wrong size returned (%d)", len(pubKeyVal))
		}
	}

	copy(key[:], pubKeyVal[:])
	return key, nil
}

// derive a shared secret using the input public key against the private key that was found during setup
// returns a fixed 32 byte array
func (client *Hsm) sharedSecret(peerPubKey NoisePublicKey) (secret [NoisePrivateKeySize]byte, err error) {
	var nullKey [NoisePublicKeySize]byte // temp garbage key (all 0's) so we can return the error

	var mech_mech uint = pkcs11.CKM_ECDH1_DERIVE

	// before we call derive, we need to have an array of attributes which specify the type of
	// key to be returned, in our case, it's the shared secret key, produced via deriving
	// This template pulled from OpenSC pkcs11-tool.c line 4038
	attrTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
	}

	// setup the parameters which include the peer's public key
	ecdhParams := pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, peerPubKey[:])

	var mech *pkcs11.Mechanism = pkcs11.NewMechanism(mech_mech, ecdhParams)

	// derive the secret key from the public key as input and the private key on the device
	tmpKey, err := p11.PrivateKey(client.privKeyObj).Derive(*mech, attrTemplate)
	if err != nil {
		return nullKey, err
	}
	if len(tmpKey) != NoisePrivateKeySize {
		return nullKey, fmt.Errorf("Wrong size derived (%d)", len(tmpKey))
	}
	copy(secret[:], tmpKey[:])
	return secret, nil
}

// Try to find a suitable key on the hsm for x25519 key derivation
func (dev *Hsm) findDeriveKey() (keys DeriveKeyPair, err error) {
	rawOID, _ := hex.DecodeString(CURVE25519_OID_RAW)
	keys = DeriveKeyPair{}

	privateAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, rawOID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
	}

	// FindObject expects a single key with above attrs, otherwise it returns err
	keys.privateKey, err = dev.session.FindObject(privateAttrs)
	if err != nil {
		return keys, fmt.Errorf("Could not find private key with attrs: %w", err)
	}

	ckaId, err := keys.privateKey.Attribute(pkcs11.CKA_ID)
	if err != nil {
		return keys, fmt.Errorf("Could not find CKA_ID of private key: %w", err)
	}

	publicAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, rawOID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ckaId),
	}

	keys.publicKey, err = dev.session.FindObject(publicAttrs)
	if err != nil {
		return keys, fmt.Errorf("Could not find public key: %w", err)
	}

	return keys, nil
}
