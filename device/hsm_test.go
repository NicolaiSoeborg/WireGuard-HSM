/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2026 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// hsmEnvOrSkip reads HSM configuration from environment variables, skipping
// the test if any required variable is absent.
//
//	WG_HSM_MODULE=/path/to/pkcs11/module.so
//	WG_HSM_SLOT=0
//	WG_HSM_PIN=123456
func hsmEnvOrSkip(t *testing.T) (modPath string, slot uint, pin string) {
	t.Helper()
	modPath = os.Getenv("WG_HSM_MODULE")
	slotStr := os.Getenv("WG_HSM_SLOT")
	pin = os.Getenv("WG_HSM_PIN")
	if modPath == "" || slotStr == "" || pin == "" {
		t.Skip("HSM tests require WG_HSM_MODULE, WG_HSM_SLOT, and WG_HSM_PIN to be set")
	}
	slotU, err := strconv.ParseUint(slotStr, 10, 32)
	if err != nil {
		t.Fatalf("Invalid WG_HSM_SLOT %q: %v", slotStr, err)
	}
	return modPath, uint(slotU), pin
}

func hsmFromEnv(t *testing.T) *Hsm {
	t.Helper()
	modPath, slot, pin := hsmEnvOrSkip(t)
	hsm, err := InitHsm(modPath, slot, pin)
	if err != nil {
		t.Fatalf("InitHsm failed: %v", err)
	}
	t.Cleanup(hsm.Close)
	return hsm
}

// TestHsmInit verifies that InitHsm succeeds with valid PIN and
// returns errors for invalid PINs.
func TestHsmInit(t *testing.T) {
	modPath, slot, pin := hsmEnvOrSkip(t)

	t.Run("Valid PIN", func(t *testing.T) {
		hsm, err := InitHsm(modPath, slot, pin)
		if err != nil {
			t.Fatalf("InitHsm with valid PIN failed: %v", err)
		}
		defer hsm.Close()
		if hsm.IsZero() {
			t.Fatal("expected IsZero() == false after successful init")
		}
	})

	t.Run("Invalid module path", func(t *testing.T) {
		_, err := InitHsm("/nonexistent/pkcs11-module.so", slot, pin)
		if err == nil {
			t.Fatal("expected error for invalid module path, got nil")
		}
	})

	t.Run("Invalid slot", func(t *testing.T) {
		_, err := InitHsm(modPath, ^uint(0), pin)
		if err == nil {
			t.Fatal("expected error for out-of-range slot, got nil")
		}
	})

	t.Run("Wrong PIN", func(t *testing.T) {
		_, err := InitHsm(modPath, slot, "wrongpin")
		if err == nil {
			t.Fatal("expected error for wrong PIN, got nil")
		}
	})
}

// TestHsmIsZero verifies that IsZero returns false for a successfully
// initialized HSM.
func TestHsmIsZero(t *testing.T) {
	hsm := hsmFromEnv(t)
	if hsm.IsZero() {
		t.Fatal("IsZero() == true for initialized HSM, expected false")
	}
}

// TestHsmSerialize verifies the serialized form is "hsm=<modPath>,<slot>" and
// does not expose the PIN.
func TestHsmSerialize(t *testing.T) {
	modPath, slot, _ := hsmEnvOrSkip(t)
	hsm := hsmFromEnv(t)
	got := hsm.Serialize()
	want := fmt.Sprintf("hsm=%s,%d", modPath, slot)
	if got != want {
		t.Fatalf("Serialize() = %q, want %q", got, want)
	}
}

// TestHsmPublicKey verifies that PublicKey returns a valid, non-zero 32-byte
// Curve25519 public key from the hardware token.
func TestHsmPublicKey(t *testing.T) {
	hsm := hsmFromEnv(t)
	pub, err := hsm.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() failed: %v", err)
	}
	var nullKey NoisePublicKey
	if pub == nullKey {
		t.Fatal("PublicKey() returned all-zero key")
	}
	t.Logf("HSM public key: %x", pub)
}

// TestHsmSharedSecretSymmetry verifies ECDH symmetry: the shared secret
// computed by the HSM using a software peer's public key must equal the shared
// secret computed by that software key using the HSM's public key.
func TestHsmSharedSecretSymmetry(t *testing.T) {
	hsm := hsmFromEnv(t)

	// Generate a fresh software keypair to act as the remote peer.
	peerSk, err := newPrivateKey()
	assertNil(t, err)
	peerPk := peerSk.publicKey()

	// HSM side: derive shared secret using the software peer's public key.
	hsmDerivedSecret, err := hsm.sharedSecret(peerPk)
	if err != nil {
		t.Fatalf("HSM sharedSecret() failed: %v", err)
	}

	// Software side: derive shared secret using the HSM's public key.
	hsmPub, err := hsm.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() failed: %v", err)
	}
	softwareDerivedSecret, err := peerSk.sharedSecret(hsmPub)
	if err != nil {
		t.Fatalf("software sharedSecret() failed: %v", err)
	}

	// ECDH symmetry: both sides must arrive at the same shared secret.
	assertEqual(t, hsmDerivedSecret[:], softwareDerivedSecret[:])
}

// TestHsmSharedSecretConsistency verifies that repeated ECDH derivations with
// the same peer key produce an identical result.
func TestHsmSharedSecretConsistency(t *testing.T) {
	hsm := hsmFromEnv(t)

	peerSk, err := newPrivateKey()
	assertNil(t, err)
	peerPk := peerSk.publicKey()

	secret1, err := hsm.sharedSecret(peerPk)
	if err != nil {
		t.Fatalf("first sharedSecret() failed: %v", err)
	}
	secret2, err := hsm.sharedSecret(peerPk)
	if err != nil {
		t.Fatalf("second sharedSecret() failed: %v", err)
	}

	assertEqual(t, secret1[:], secret2[:])
}

// TestHsmSharedSecretDiffers verifies that different peer keys produce
// different shared secrets.
func TestHsmSharedSecretDiffers(t *testing.T) {
	hsm := hsmFromEnv(t)

	sk1, err := newPrivateKey()
	assertNil(t, err)
	sk2, err := newPrivateKey()
	assertNil(t, err)

	ss1, err := hsm.sharedSecret(sk1.publicKey())
	if err != nil {
		t.Fatalf("sharedSecret() for key1 failed: %v", err)
	}
	ss2, err := hsm.sharedSecret(sk2.publicKey())
	if err != nil {
		t.Fatalf("sharedSecret() for key2 failed: %v", err)
	}

	if ss1 == ss2 {
		t.Fatal("sharedSecret() returned the same value for two different peer keys")
	}
}

// TestHsmNoiseHandshake runs a full WireGuard Noise handshake where device 1
// uses the physical HSM for its static private key and device 2 uses a
// software key. Verifies that both sides derive identical session keys and
// that messages can be exchanged using those keys.
func TestHsmNoiseHandshake(t *testing.T) {
	// Device 1 is backed by the hardware token.
	hsm := hsmFromEnv(t)
	tun1 := tuntest.NewChannelTUN()
	dev1 := NewDevice(tun1.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, "hsm: "))
	if err := dev1.SetPrivateKey(hsm); err != nil {
		t.Fatalf("SetPrivateKey(hsm) failed: %v", err)
	}
	defer dev1.Close()

	// Device 2 uses a software key.
	dev2 := randDevice(t)
	defer dev2.Close()

	// Register each device as a peer of the other.
	pk1, err := dev1.staticIdentity.privateKey.PublicKey()
	if err != nil {
		t.Fatalf("failed to get HSM public key: %v", err)
	}
	peer1, err := dev2.NewPeer(pk1)
	if err != nil {
		t.Fatalf("dev2.NewPeer failed: %v", err)
	}

	pk2, err := dev2.staticIdentity.privateKey.PublicKey()
	assertNil(t, err)
	peer2, err := dev1.NewPeer(pk2)
	if err != nil {
		t.Fatalf("dev1.NewPeer failed: %v", err)
	}

	peer1.Start()
	peer2.Start()

	// Both sides must have computed the same static-static shared secret.
	assertEqual(
		t,
		peer1.handshake.precomputedStaticStatic[:],
		peer2.handshake.precomputedStaticStatic[:],
	)

	// Initiation message (HSM device → software device).
	t.Log("exchange initiation message")
	msg1, err := dev1.CreateMessageInitiation(peer2)
	assertNil(t, err)

	if dev2.ConsumeMessageInitiation(msg1) == nil {
		t.Fatal("handshake failed at initiation message")
	}

	assertEqual(t, peer1.handshake.chainKey[:], peer2.handshake.chainKey[:])
	assertEqual(t, peer1.handshake.hash[:], peer2.handshake.hash[:])

	// Response message (software device → HSM device).
	t.Log("exchange response message")
	msg2, err := dev2.CreateMessageResponse(peer1)
	assertNil(t, err)

	if dev1.ConsumeMessageResponse(msg2) == nil {
		t.Fatal("handshake failed at response message")
	}

	assertEqual(t, peer1.handshake.chainKey[:], peer2.handshake.chainKey[:])
	assertEqual(t, peer1.handshake.hash[:], peer2.handshake.hash[:])

	// Derive symmetric session keys from the completed handshake.
	t.Log("deriving session keys")
	if err := peer1.BeginSymmetricSession(); err != nil {
		t.Fatalf("peer1 BeginSymmetricSession failed: %v", err)
	}
	if err := peer2.BeginSymmetricSession(); err != nil {
		t.Fatalf("peer2 BeginSymmetricSession failed: %v", err)
	}

	key1 := peer1.keypairs.next.Load()
	key2 := peer2.keypairs.current

	// Verify encryption in both directions.
	t.Log("test key pairs")
	func() {
		testMsg := []byte("wireguard hsm test message 1")
		var out []byte
		var nonce [12]byte
		out = key1.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key2.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()

	func() {
		testMsg := []byte("wireguard hsm test message 2")
		var out []byte
		var nonce [12]byte
		out = key2.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key1.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()
}
