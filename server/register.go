package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

type RegistrationRequest struct {
	Tail      string `json:"tail"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

type RegistrationResponse struct {
	ServerKey string `json:"server_public_key"`
	Status    string `json:"status"`
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Use POST", http.StatusMethodNotAllowed)
		return
	}

	var req RegistrationRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Read error", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Bad JSON", http.StatusBadRequest)
		return
	}

	pubKey, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pubKey) != ed25519.PublicKeySize {
		http.Error(w, "Invalid public key", http.StatusBadRequest)
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return
	}

	// Verify signature on message: "register:<tail>"
	verificationMsg := []byte("register:" + req.Tail)
	if !ed25519.Verify(pubKey, verificationMsg, sig) {
		http.Error(w, "Signature mismatch", http.StatusUnauthorized)
		return
	}

	// Save public key to keys directory
	os.MkdirAll("keys", 0700)
	dest := filepath.Join("keys", fmt.Sprintf("%s.pub", req.Tail))
	os.WriteFile(dest, pubKey, 0600)
	fmt.Printf("[+] Registered plane %s with pubkey saved to %s\n", req.Tail, dest)

	// Load server pubkey to respond
	serverPub, err := os.ReadFile("keys/server.pub")
	if err != nil {
		http.Error(w, "Server key missing", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(RegistrationResponse{
		ServerKey: base64.StdEncoding.EncodeToString(serverPub),
		Status:    "ok",
	})
}

func registerRoutes() {
	http.HandleFunc("/register", handleRegister)
}
