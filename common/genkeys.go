package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Key generation failed:", err)
		os.Exit(1)
	}

	fmt.Println("Public Key (base64):")
	fmt.Println(base64.StdEncoding.EncodeToString(pub))

	fmt.Println("\nPrivate Key (base64):")
	fmt.Println(base64.StdEncoding.EncodeToString(priv))

	// Optionally save to file
	if len(os.Args) == 2 {
		tail := os.Args[1]
		os.MkdirAll("keys", 0700)
		os.WriteFile(fmt.Sprintf("keys/%s.pub", tail), pub, 0600)
		os.WriteFile(fmt.Sprintf("keys/%s.key", tail), priv, 0600)
		fmt.Printf("\n[+] Keypair saved for %s in ./keys/\n", tail)
	}
}
