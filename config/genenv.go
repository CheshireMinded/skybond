package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func prompt(label string) string {
	fmt.Print(label)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func writeEnvFile(tail, serverIP, pubKey, privKey, hmacKey string) error {
	env := fmt.Sprintf(`TAIL=%s
SERVER_IP=%s
PLANE_PUBLIC_KEY=%s
PLANE_PRIVATE_KEY=%s
SERVER_PUBLIC_KEY=
HMAC_SECRET_KEY=%s
`, tail, serverIP, pubKey, privKey, hmacKey)

	return os.WriteFile(".env", []byte(env), 0600)
}

func encryptEnvFile() error {
	cmd := exec.Command("gpg", "--symmetric", "--cipher-algo", "AES256", ".env")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func main() {
	fmt.Println("Skybond ENV Generator")

	tail := prompt("Enter aircraft tail number (e.g. N123AB): ")
	serverIP := prompt("Enter server IP (e.g. 192.168.89.214): ")

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	hmacKey := make([]byte, 32)
	rand.Read(hmacKey)

	pubStr := base64.StdEncoding.EncodeToString(pub)
	privStr := base64.StdEncoding.EncodeToString(priv)
	hmacStr := base64.StdEncoding.EncodeToString(hmacKey)

	if err := writeEnvFile(tail, serverIP, pubStr, privStr, hmacStr); err != nil {
		fmt.Println("Failed to write .env:", err)
		return
	}

	if err := encryptEnvFile(); err != nil {
		fmt.Println("Failed to encrypt .env:", err)
		return
	}

	os.Remove(".env")
	fmt.Println(".env.gpg created and .env removed.")
}
