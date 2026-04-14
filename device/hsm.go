/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2026 WireGuard LLC. All Rights Reserved.
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
	session    p11.Session // PKCS#11 session object
	privKeyObj p11.Object  // ref to private key on HSM
	pubKeyObj  p11.Object  // ref to public key on HSM
	module     p11.Module  // PKCS#11 library to communicate with HSM
	serialized string
	isReady    bool
}

// Open a session with the HSM, select the slot and login to unlock the HSM
// A public and private key must already exist on the HSM and the private
// key must have "EC domain parameters" set to id-X25519 (1.3.101.110)
func InitHsm(modPath string, slot uint, pin string) (*Hsm, error) {
	client := new(Hsm)
	client.isReady = false

	module, err := p11.OpenModule(modPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to load module library: %s. Error: %w", modPath, err)
	}
	client.module = module

	slots, err := module.Slots()
	if err != nil {
		return nil, err
	}

	if uint(len(slots)) <= slot {
		return nil, fmt.Errorf("Requested slot (%d) but only %d available", slot, len(slots))
	}

	client.session, err = slots[slot].OpenSession()
	if err != nil {
		return nil, fmt.Errorf("Failed to open session on slot %d. Error: %w", slot, err)
	}

	err = client.session.Login(pin)
	if err != nil {
		return nil, fmt.Errorf("Unable to login: %w", err)
	}

	X25519KeyPair, err := client.findDeriveKey()
	if err != nil {
		return nil, fmt.Errorf("Failed to find X25519 key for deriving: %w", err)
	}

	client.pubKeyObj = X25519KeyPair.publicKey
	client.privKeyObj = X25519KeyPair.privateKey
	client.serialized = fmt.Sprintf("hsm=%s,%d", modPath, slot)
	client.isReady = true

	return client, nil
}

// A "zero key" in software means we don't know the key yet
// For HSM this means the HSM isn't ready
func (client *Hsm) IsZero() bool {
	return !client.isReady
}

func (client *Hsm) Serialize() string {
	return client.serialized
}

func (client *Hsm) Close() {
	client.isReady = false
	if client.session != nil {
		client.session.Logout()
		client.session.Close()
		client.session = nil
	}
	client.module.Destroy()
}

func (client *Hsm) PublicKey() (key NoisePublicKey, err error) {
	var nullKey NoisePublicKey // temp garbage key (all 0's) so we can return an error

	// "DER-encoding of the public key value in little endian order as defined in RFC 7748"
	// - https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cs01/pkcs11-curr-v3.0-cs01.html
	pubKeyVal, err := client.pubKeyObj.Attribute(pkcs11.CKA_EC_POINT)
	if err != nil {
		return nullKey, err
	}

	// Prefix is "\x04 (OCTET STRING) \x20 (of length 32)" followed by the raw key
	if len(pubKeyVal) == NoisePublicKeySize+2 && pubKeyVal[0] == 0x04 && pubKeyVal[1] == 0x20 {
		pubKeyVal = pubKeyVal[2:]
	} else {
		return nullKey, fmt.Errorf("Key of wrong size or prefix returned (got %d bytes)", len(pubKeyVal))
	}

	copy(key[:], pubKeyVal[:])
	return key, nil
}

func (client *Hsm) sharedSecret(peerPubKey NoisePublicKey) (secret [NoisePrivateKeySize]byte, err error) {
	var nullKey [NoisePublicKeySize]byte // temp garbage key (all 0's) so we can return an error

	// https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cs01/pkcs11-curr-v3.0-cs01.html
	// NewECDH1DeriveParams(kdf uint, sharedData []byte, publicKeyData []byte)
	// kdf           => "key derivation function used on the shared secret value"
	// sharedData    => "some data shared between the two parties"
	// publicKeyData => "[...] other party’s EC public key value. A token MUST be able to accept this value encoded as a raw octet string"
	ecdhParams := pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, peerPubKey[:])

	var deriveMech *pkcs11.Mechanism = pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, ecdhParams)

	// Before we call derive, we need to have an array of attributes which specify the type of
	// key (shared secret) to be returned
	attrTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET), // output (shared secret) is a raw byte string with no structure ("generic secret")
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),                        // we want to derive a "session object" (temporary for this session only)
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),                   // shared secret can be exported to software
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),                    // shared secret can be exported raw
	}

	// derive the secret key from the public key as input and the private key on the device
	ss, err := p11.PrivateKey(client.privKeyObj).Derive(*deriveMech, attrTemplate)
	if err != nil {
		return nullKey, err
	}
	if len(ss) != NoisePrivateKeySize {
		return nullKey, fmt.Errorf("Shared secret of wrong size derived (%d bytes)", len(ss))
	}
	copy(secret[:], ss[:])
	return secret, nil
}

// Try to find a suitable key on the hsm for x25519 key derivation
func (dev *Hsm) findDeriveKey() (keys DeriveKeyPair, err error) {
	rawOID, _ := hex.DecodeString(CURVE25519_OID_RAW)
	keys = DeriveKeyPair{}

	// Find a private X25519 key that is allowed to derive
	privateAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),       // look only for "token objects" (persisted on HSM)
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, rawOID), // private key be specified on the id-X25519 curve
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),      // private key should be allowed to derive a shared secret
	}

	// FindObject expects a single key with above attrs, otherwise it returns err
	keys.privateKey, err = dev.session.FindObject(privateAttrs)
	if err != nil {
		return keys, fmt.Errorf("Could not find private key with attrs: %w", err)
	}

	// "The CKA_ID attribute is intended as a means of distinguishing multiple public-key/private-key pairs"
	// Note: This might only be relevant for X.509 certificates? By default this value is empty.
	ckaId, err := keys.privateKey.Attribute(pkcs11.CKA_ID)
	if err != nil {
		return keys, fmt.Errorf("Could not find CKA_ID of private key: %w", err)
	}

	publicAttrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),       // look only for "token objects" (persisted on HSM)
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, rawOID), // public key be specified on the id-X25519 curve
		pkcs11.NewAttribute(pkcs11.CKA_ID, ckaId),
	}

	keys.publicKey, err = dev.session.FindObject(publicAttrs)
	if err != nil {
		return keys, fmt.Errorf("Could not find public key: %w", err)
	}

	return keys, nil
}
