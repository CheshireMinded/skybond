package server

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var alertMutex sync.Mutex

// Serve the main dashboard view with live feeds
func serveAdminDashboard(w http.ResponseWriter, r *http.Request) {
	const html = `<!DOCTYPE html>
<html>
<head>
  <title>SkyBond Dashboard</title>
  <meta http-equiv="refresh" content="5">
  <style>
    body { font-family: sans-serif; background-color: #f8f8f8; }
    nav { margin-bottom: 20px; }
    video { width: 320px; height: 180px; margin: 10px; border: 1px solid #444; }
    .panel { background: #fff; padding: 10px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 5px; color: white; font-weight: bold; font-size: 0.8em; }
    .green { background-color: green; }
    .red { background-color: red; }
    .tabs { margin-top: 20px; }
    .tabs a { margin-right: 15px; }
  </style>
</head>
<body>
  <h1>SkyBond Mission Dashboard</h1>
  <nav class="tabs">
    <a href="/admin">Live Feeds</a> |
    <a href="/admin/stats">Stats</a> |
    <a href="/admin/dhcp">DHCP</a> |
    <a href="/admin/logs">Logs</a> |
    <a href="/metrics">Metrics</a>
  </nav>
  {{range .}}
    <div class="panel">
      <h3>Tail: {{.Tail}} <span class="badge {{.StatusColor}}">{{.Status}}</span> | Uptime: {{.Uptime}}</h3>
      <video id="vid_{{.Tail}}" src="{{.URL}}" controls autoplay muted></video>
      <p>
        <a href="{{.Stream}}">Stream</a> |
        <a href="{{.URL}}" download>Download</a>
      </p>
    </div>
  {{end}}
</body>
</html>`
	tmpl := template.Must(template.New("admin").Parse(html))
	tmpl.Execute(w, getPlanesStatus())
}

// Serve the stats page with heartbeat frequency graph using Chart.js
func serveStatsPage(w http.ResponseWriter, r *http.Request) {
	const html = `<!DOCTYPE html>
<html>
<head>
  <title>SkyBond Stats</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
  <h1>Heartbeat Frequency</h1>
  <canvas id="chart" width="800" height="400"></canvas>
  <script>
    fetch('/admin/stats/data').then(r => r.json()).then(data => {
      const ctx = document.getElementById('chart').getContext('2d');
      const datasets = data.tails.map((tail, i) => ({
        label: tail,
        data: data.data[tail],
        
        fill: false,
        lineTension: 0.1
      }));
      new Chart(ctx, {
        type: 'line',
        data: { labels: data.labels, datasets },
        options: { 
          responsive: true,
          plugins: { tooltip: { mode: 'index', intersect: false } },
          scales: {
            x: { 
              title: { display: true, text: 'Time' } 
            },
            y: { 
              title: { display: true, text: 'Heartbeat Count' } 
            }
          }
        }
      });
    });
  </script>
</body>
</html>`
	w.Write([]byte(html))
}

// Serve the DHCP page with current DHCP configuration and leases
func serveDHCPPage(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("cat", "/etc/dnsmasq.d/starlink.conf")
	out, err := cmd.Output()
	if err != nil {
		http.Error(w, "Failed to read DHCP config", 500)
		return
	}

	leases, _ := os.ReadFile("/var/lib/misc/dnsmasq.leases")
	html := "<h2>dnsmasq.conf</h2><pre>" + template.HTMLEscapeString(string(out)) + "</pre>"
	html += "<h2>dnsmasq.leases</h2><pre>" + template.HTMLEscapeString(string(leases)) + "</pre>"
	w.Write([]byte(html))
}

// Serve the logs page with recent alerts
func serveLogsPage(w http.ResponseWriter, r *http.Request) {
	alertMutex.Lock()
	defer alertMutex.Unlock()
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<h1>Recent Alerts</h1><ul>"))
	for _, alert := range alerts {
		w.Write([]byte("<li>" + template.HTMLEscapeString(alert) + "</li>"))
	}
	w.Write([]byte("</ul>"))
}

// Register all dashboard routes
func registerDashboardRoutes() {
	http.HandleFunc("/admin", requireAuth(serveAdminDashboard))
	http.HandleFunc("/admin/stats", requireAuth(serveStatsPage))
	http.HandleFunc("/admin/dhcp", requireAuth(serveDHCPPage))
	http.HandleFunc("/admin/logs", requireAuth(serveLogsPage))
	http.HandleFunc("/admin/stats/data", requireAuth(serveHeartbeatStatsJSON))
	http.Handle("/metrics", promhttp.Handler())
}

// Function to get status of all planes (e.g., online/offline, latest video)
func getPlanesStatus() []map[string]string {
	entries := []map[string]string{}
	dirEntries, _ := os.ReadDir("uploads")
	for _, entry := range dirEntries {
		tail := entry.Name()
		files, err := os.ReadDir(filepath.Join("uploads", tail))
		if err != nil || len(files) == 0 {
			continue
		}
		latest := files[len(files)-1].Name()
		status := "Offline"
		color := "red"
		info, err := os.Stat(filepath.Join("uploads", tail, latest))
		if err == nil && time.Since(info.ModTime()) < 5*time.Minute {
			status = "Online"
			color = "green"
		}
		uptime := time.Since(info.ModTime()).Truncate(time.Second).String()
		entries = append(entries, map[string]string{
			"Tail":        tail,
			"URL":         "/uploads/" + tail + "/" + latest,
			"Stream":      "/stream/" + tail,
			"Status":      status,
			"StatusColor": color,
			"Uptime":      uptime,
		})
	}
	return entries
}

// Serve heartbeat stats in JSON format for Chart.js
func serveHeartbeatStatsJSON(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open("sqlite3", config.DBFile)
	if err != nil {
		http.Error(w, "DB error", 500)
		return
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT tail, strftime('%H:%M', timestamp) AS minute, COUNT(*) 
		FROM heartbeats 
		WHERE timestamp >= datetime('now', '-60 minutes') 
		GROUP BY tail, minute 
		ORDER BY minute ASC`)
	if err != nil {
		http.Error(w, "Query error", 500)
		return
	}
	defer rows.Close()

	type countMap map[string][]int
	labels := []string{}
	tailData := make(map[string]map[string]int)
	tailSet := make(map[string]struct{})
	labelSet := make(map[string]struct{})

	for rows.Next() {
		var tail, minute string
		var count int
		rows.Scan(&tail, &minute, &count)
		if _, ok := tailData[tail]; !ok {
			tailData[tail] = make(map[string]int)
		}
		tailData[tail][minute] = count
		tailSet[tail] = struct{}{}
		labelSet[minute] = struct{}{}
	}

	for minute := range labelSet {
		labels = append(labels, minute)
	}
	sort.Strings(labels)

	finalData := make(map[string][]int)
	tails := []string{}
	for tail := range tailSet {
		tails = append(tails, tail)
		row := []int{}
		for _, label := range labels {
			row = append(row, tailData[tail][label])
		}
		finalData[tail] = row
	}

	resp := map[string]interface{}{
		"tails":  tails,
		"labels": labels,
		"data":   finalData,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
