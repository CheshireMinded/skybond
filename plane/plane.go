// Package plane implements the heartbeat and audio/video upload with retry logic.
package plane

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"skybond/common"
)

var (
	config              common.Config
	secretKey           []byte
	availableInterfaces = []string{"eth0", "eth1", "eth2"}

	heartbeatQueue   []string
	avChunkQueue     []string
	queueMutex       sync.Mutex
	retryInterval    = 5 * time.Second
	heartbeatUDPPort = 9000
	heartbeatMax     = 10 // Max unsent heartbeats to keep
)

type Telemetry struct {
	Pitch float64 `json:"pitch"`
	Yaw   float64 `json:"yaw"`
	Roll  float64 `json:"roll"`
	Time  string  `json:"time"`
}

type InterfaceHealth struct {
	Name      string
	PingOK    bool
	CurlOK    bool
	Score     int
	LastCheck time.Time
}

type RegistrationRequest struct {
	Tail      string `json:"tail"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

type RegistrationResponse struct {
	ServerKey string `json:"server_public_key"`
	Status    string `json:"status"`
}

func loadConfig(path string) common.Config {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Failed to load", path, ":", err)
		os.Exit(1)
	}
	var cfg common.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Println("Invalid config:", err)
		os.Exit(1)
	}
	return cfg
}

func checkInterfaceHealth(iface string, serverIP string) InterfaceHealth {
	result := InterfaceHealth{Name: iface, LastCheck: time.Now()}

	pingCmd := exec.Command("ping", "-I", iface, "-c", "1", "-W", "1", serverIP)
	if err := pingCmd.Run(); err == nil {
		result.PingOK = true
	}

	curlCmd := exec.Command("curl", "--interface", iface, "--max-time", "2", "-s", fmt.Sprintf("http://%s", serverIP))
	var curlOut bytes.Buffer
	curlCmd.Stdout = &curlOut
	curlCmd.Stderr = &curlOut
	if err := curlCmd.Run(); err == nil {
		result.CurlOK = true
	}

	if result.PingOK {
		result.Score++
	}
	if result.CurlOK {
		result.Score++
	}
	return result
}

func selectBestInterface(serverIP string, candidates []string) string {
	best := ""
	highestScore := -1
	for _, iface := range candidates {
		status := checkInterfaceHealth(iface, serverIP)
		fmt.Printf("[*] %s: PingOK=%v CurlOK=%v Score=%d\n", iface, status.PingOK, status.CurlOK, status.Score)
		if status.Score > highestScore {
			best = iface
			highestScore = status.Score
		}
	}
	if best == "" {
		fmt.Println("[!] No good interface found. Defaulting to eth0.")
		return "eth0"
	}
	fmt.Printf("[+] Selected interface: %s\n", best)
	return best
}

func signMessage(msg string) string {
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func sendUDPHeartbeat(tail string, iface string, server string) error {
	msg := fmt.Sprintf("HEARTBEAT %s %s", tail, iface)
	sig := signMessage(msg)
	fullMsg := fmt.Sprintf("%s|%s", msg, sig)

	conn, err := net.Dial("udp", server)
	if err != nil {
		EnqueueHeartbeat(msg)
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(fullMsg))
	return err
}

func EnqueueHeartbeat(msg string) {
	queueMutex.Lock()
	defer queueMutex.Unlock()
	if len(heartbeatQueue) >= heartbeatMax {
		heartbeatQueue = heartbeatQueue[1:]
	}
	heartbeatQueue = append(heartbeatQueue, msg)
}

func RetryHeartbeats(server string, secretKey []byte) {
	queueMutex.Lock()
	queue := make([]string, len(heartbeatQueue))
	copy(queue, heartbeatQueue)
	heartbeatQueue = []string{}
	queueMutex.Unlock()

	for _, msg := range queue {
		signed := fmt.Sprintf("%s|%s", msg, signMessage(msg))
		addr := fmt.Sprintf("%s:%d", server, heartbeatUDPPort)
		conn, err := net.Dial("udp", addr)
		if err != nil {
			EnqueueHeartbeat(msg)
			continue
		}
		conn.Write([]byte(signed))
		conn.Close()
	}
}

func EnqueueAVChunk(path string) {
	queueMutex.Lock()
	defer queueMutex.Unlock()
	avChunkQueue = append(avChunkQueue, path)
}

func RetryAVChunks(server string) {
	queueMutex.Lock()
	queue := make([]string, len(avChunkQueue))
	copy(queue, avChunkQueue)
	avChunkQueue = []string{}
	queueMutex.Unlock()

	for _, file := range queue {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		req, err := http.NewRequest("POST", fmt.Sprintf("http://%s/upload", server), bytes.NewReader(data))
		if err != nil {
			EnqueueAVChunk(file)
			continue
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode >= 300 {
			EnqueueAVChunk(file)
			continue
		}
		fmt.Println("[+] Uploaded:", file)
		os.Remove(file)
	}
}

func StartRetryLoops(server string, secretKey []byte) {
	go func() {
		for {
			RetryHeartbeats(server, secretKey)
			RetryAVChunks(server)
			time.Sleep(retryInterval)
		}
	}()
}

func SaveAVChunk(data []byte) string {
	timestamp := time.Now().Unix()
	file := filepath.Join("chunks", fmt.Sprintf("chunk-%d.av", timestamp))
	os.MkdirAll("chunks", 0700)
	os.WriteFile(file, data, 0600)
	EnqueueAVChunk(file)
	return file
}

func loadKeypair(tail string) (ed25519.PublicKey, ed25519.PrivateKey) {
	pubPath := filepath.Join("keys", tail+".pub")
	privPath := filepath.Join("keys", tail+".key")
	os.MkdirAll("keys", 0700)

	pubBytes, errPub := os.ReadFile(pubPath)
	privBytes, errPriv := os.ReadFile(privPath)

	if errPub == nil && errPriv == nil {
		return ed25519.PublicKey(pubBytes), ed25519.PrivateKey(privBytes)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	os.WriteFile(pubPath, pub, 0600)
	os.WriteFile(privPath, priv, 0600)
	fmt.Println("[+] Generated new keypair for tail", tail)
	return pub, priv
}

func registerWithServer(cfg common.Config, pub ed25519.PublicKey, priv ed25519.PrivateKey) []byte {
	msg := []byte("register:" + cfg.Tail)
	sig := ed25519.Sign(priv, msg)

	req := RegistrationRequest{
		Tail:      cfg.Tail,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
	jsonBody, _ := json.Marshal(req)

	resp, err := http.Post(fmt.Sprintf("http://%s/register", cfg.ServerIP), "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		fmt.Println("Registration failed:", err)
		return nil
	}
	defer resp.Body.Close()

	var reply RegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		fmt.Println("Bad server reply:", err)
		return nil
	}

	serverPub, err := base64.StdEncoding.DecodeString(reply.ServerKey)
	if err != nil {
		fmt.Println("Invalid server public key:", err)
		return nil
	}

	os.WriteFile("keys/server.pub", serverPub, 0600)
	fmt.Println("[+] Server pubkey saved to keys/server.pub")
	return serverPub
}

func RunPlane() {
	config = loadConfig("config/config.json")
	pub, priv := loadKeypair(config.Tail)

	var serverPub []byte
	for i := 0; i < 3; i++ {
		serverPub = registerWithServer(config, pub, priv)
		if len(serverPub) > 0 {
			break
		}
		fmt.Println("[!] Retry registration in 5s...")
		time.Sleep(5 * time.Second)
	}
	if len(serverPub) == 0 {
		fmt.Println("[!] Registration failed after 3 attempts.")
		os.Exit(1)
	}

	secretKey = serverPub[:32] // HMAC key
	StartRetryLoops(config.ServerIP, secretKey)
	sendHeartbeat(config.Tail, config.ServerIP)
}
