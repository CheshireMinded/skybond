package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"skybond/common"

	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

var config common.Config
var alerts []string
var mu sync.Mutex

type Heartbeat struct {
	Tail      string
	Interface string
	Timestamp string
}

func loadConfig(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Failed to load config.json:", err)
		os.Exit(1)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		fmt.Println("Invalid config format:", err)
		os.Exit(1)
	}
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != config.AuthUser || pass != config.AuthPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="Heartbeat Server"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func logHeartbeat(tail string, iface string) {
	db, err := sql.Open("sqlite3", config.DBFile)
	if err != nil {
		recordAlert("DB open fail: " + err.Error())
		return
	}
	defer db.Close()

	stmt, err := db.Prepare("INSERT INTO heartbeats(tail, iface, timestamp) VALUES (?, ?, ?)")
	if err != nil {
		recordAlert("DB prepare fail: " + err.Error())
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(tail, iface, time.Now().Format(time.RFC3339))
	if err != nil {
		recordAlert("DB exec fail: " + err.Error())
	}
}

func verifySignature(message, signature string) bool {
	mac := hmac.New(sha256.New, []byte(config.SecretKey))
	mac.Write([]byte(message))
	expectedMAC := mac.Sum(nil)
	receivedMAC, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	return hmac.Equal(expectedMAC, receivedMAC)
}

func recordAlert(reason string) {
	mu.Lock()
	defer mu.Unlock()
	entry := fmt.Sprintf("%s: %s", time.Now().Format(time.RFC3339), reason)
	alerts = append(alerts, entry)
	fmt.Println("ALERT:", entry)
}

func RunServer() {
	loadConfig("config/config.json") // Match directory layout
	registerRoutes()                 // From register.go
	go runDashboard()

	ln, err := net.ListenPacket("udp", ":9000")
	if err != nil {
		fmt.Println("Failed to start UDP listener:", err)
		return
	}
	defer ln.Close()

	buf := make([]byte, 1024)
	for {
		n, _, err := ln.ReadFrom(buf)
		if err != nil {
			recordAlert("UDP read error: " + err.Error())
			continue
		}

		data := string(buf[:n])
		parts := strings.Split(data, "|")
		if len(parts) != 2 {
			recordAlert("Invalid message format (no signature)")
			continue
		}

		message := parts[0]
		signature := parts[1]

		if !verifySignature(message, signature) {
			recordAlert("Invalid signature: message rejected")
			continue
		}

		var tail, iface string
		if _, err := fmt.Sscanf(message, "HEARTBEAT %s %s", &tail, &iface); err != nil {
			recordAlert("Malformed heartbeat: " + err.Error())
			continue
		}

		fmt.Printf("Heartbeat from %s on %s (verified)\n", tail, iface)
		logHeartbeat(tail, iface)
	}
}

func runDashboard() {
	http.HandleFunc("/", requireAuth(serveUI))
	http.HandleFunc("/data", requireAuth(handleData))
	http.HandleFunc("/alerts", requireAuth(handleAlerts))
	http.HandleFunc("/export", requireAuth(handleExport))

	fmt.Println("Dashboard live at http://localhost:8081 (auth required)")
	if err := http.ListenAndServe(":8081", nil); err != nil {
		fmt.Println("HTTP server crash:", err)
	}
}

func serveUI(w http.ResponseWriter, r *http.Request) {
	const html = `<!DOCTYPE html>
<html>
<head>
    <title>Heartbeat Dashboard</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body { font-family: sans-serif; background: #f9f9f9; padding: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-top: 10px; }
        th, td { padding: 8px; border: 1px solid #ddd; text-align: left; }
        .alert { background: #ffe0e0; padding: 8px; margin-top: 20px; }
    </style>
</head>
<body>
    <h1> Verified Heartbeats</h1>
    <table>
        <tr><th>Tail</th><th>Interface</th><th>Timestamp</th></tr>
        {{range .Heartbeats}}
        <tr><td>{{.Tail}}</td><td>{{.Interface}}</td><td>{{.Timestamp}}</td></tr>
        {{end}}
    </table>

    <h2> Alerts</h2>
    {{range .Alerts}}
    <div class="alert">{{.}}</div>
    {{end}}

    <p><a href="/export">Export to CSV</a></p>
</body>
</html>`

	db, err := sql.Open("sqlite3", config.DBFile)
	if err != nil {
		http.Error(w, "DB error", 500)
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT tail, iface, timestamp FROM heartbeats ORDER BY timestamp DESC LIMIT 10")
	if err != nil {
		http.Error(w, "Query error", 500)
		return
	}
	defer rows.Close()

	var results []Heartbeat
	for rows.Next() {
		var h Heartbeat
		rows.Scan(&h.Tail, &h.Interface, &h.Timestamp)
		results = append(results, h)
	}

	mu.Lock()
	pageAlerts := make([]string, len(alerts))
	copy(pageAlerts, alerts)
	mu.Unlock()

	tmpl, _ := template.New("dashboard").Parse(html)
	tmpl.Execute(w, map[string]interface{}{
		"Heartbeats": results,
		"Alerts":     pageAlerts,
	})
}

func handleData(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", config.DBFile)
	if err != nil {
		http.Error(w, "DB error", 500)
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT tail, iface, timestamp FROM heartbeats ORDER BY timestamp DESC LIMIT 10")
	if err != nil {
		http.Error(w, "Query error", 500)
		return
	}
	defer rows.Close()

	var results []Heartbeat
	for rows.Next() {
		var h Heartbeat
		rows.Scan(&h.Tail, &h.Interface, &h.Timestamp)
		results = append(results, h)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func handleAlerts(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func handleExport(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", config.DBFile)
	if err != nil {
		http.Error(w, "DB error", 500)
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT tail, iface, timestamp FROM heartbeats ORDER BY timestamp ASC")
	if err != nil {
		http.Error(w, "Query error", 500)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Disposition", "attachment;filename=heartbeats.csv")
	w.Header().Set("Content-Type", "text/csv")
	csvWriter := csv.NewWriter(w)
	csvWriter.Write([]string{"tail", "interface", "timestamp"})

	for rows.Next() {
		var tail, iface, timestamp string
		rows.Scan(&tail, &iface, &timestamp)
		csvWriter.Write([]string{tail, iface, timestamp})
	}
	csvWriter.Flush()
}
