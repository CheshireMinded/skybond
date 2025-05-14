// keyexchange.go - Secure key generation and exchange for Skybond

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
)

const (
	keyDir      = "keys"
	privKeyFile = "private.key"
	peerKeyFile = "peer.key"
	serverURL   = "http://192.168.89.214:8080/register"
)

// generateKeypair creates and saves Ed25519 private/public key pair
func generateKeypair() error {
	if _, err := os.Stat(path.Join(keyDir, privKeyFile)); err == nil {
		fmt.Println("[!] Keypair already exists, skipping generation")
		return nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	os.MkdirAll(keyDir, 0700)
	ioutil.WriteFile(path.Join(keyDir, privKeyFile), priv, 0600)
	ioutil.WriteFile(path.Join(keyDir, "public.key"), pub, 0644)
	fmt.Println("[+] New keypair generated and saved.")
	return nil
}

type KeyExchangePayload struct {
	Tail      string `json:"tail"`
	PubKey    string `json:"pubkey"`
	Signature string `json:"sig"`
}

func exchangeKeys(tail string) error {
	priv, err := ioutil.ReadFile(path.Join(keyDir, privKeyFile))
	if err != nil {
		return fmt.Errorf("missing private key: %w", err)
	}
	pub := priv[32:]

	msg := []byte(tail)
	sig := ed25519.Sign(priv, msg)

	payload := KeyExchangePayload{
		Tail:      tail,
		PubKey:    hex.EncodeToString(pub),
		Signature: hex.EncodeToString(sig),
	}
	jsonData, _ := json.Marshal(payload)

	resp, err := http.Post(serverURL, "application/json", bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("post error: %w", err)
	}
	defer resp.Body.Close()

	peerPubKeyHex, _ := ioutil.ReadAll(resp.Body)
	ioutil.WriteFile(path.Join(keyDir, peerKeyFile), peerPubKeyHex, 0644)
	fmt.Println("[+] Server public key saved.")
	return nil
}

func initKeySystem(tail string) {
	if err := generateKeypair(); err != nil {
		fmt.Println("[!] Failed to generate keys:", err)
		os.Exit(1)
	}
	if err := exchangeKeys(tail); err != nil {
		fmt.Println("[!] Key exchange failed:", err)
		os.Exit(1)
	}
}
