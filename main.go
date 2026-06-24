package main

import (
	"bufio"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"

	"golang.org/x/crypto/bcrypt"
)

// ====== 配置 ======
var (
	ProbeIP      = getEnv("PROBE_IP", "0.0.0.0")
	ProbePort    = getEnv("PROBE_PORT", "8082")
	ListenAddr   = ProbeIP + ":" + ProbePort
	DBPath       = getEnv("PROBE_DB", "/root/probe/probe.db")
	PollInterval = 10 * time.Second
	BcryptCost   = 12
)

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ====== 类型定义 ======
type SysStats struct {
	CPU     float64 `json:"cpu_percent"`
	MemUsed int64   `json:"mem_used_bytes"`
	MemTotal int64   `json:"mem_total_bytes"`
	DiskUsed int64   `json:"disk_used_bytes"`
	DiskTotal int64   `json:"disk_total_bytes"`
}

type DailyTraffic struct {
	Date    string `json:"date"`
	RxDelta int64  `json:"rx_delta"`
	TxDelta int64  `json:"tx_delta"`
}

type MonthlyTraffic struct {
	MonthKey string `json:"month_key"`
	RxDelta  int64  `json:"rx_delta"`
	TxDelta  int64  `json:"tx_delta"`
}

type DashboardData struct {
	Stats           SysStats
	MonthRx         int64
	MonthTx         int64
	TodayRx         int64
	TodayTx         int64
	MonthKey        string
	DailyTraffic    []DailyTraffic
	MonthlyHistory  []MonthlyTraffic
	Interfaces      []string
	Uptime          string
	LastCollectTime string
}

// ====== 全局变量 ======
var (
	db      *sql.DB
	statsMu sync.Mutex
	latest  SysStats
)

// ====== 辅助函数 ======
func readProcFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// ====== CPU ======
type cpuSample struct {
	user, nice, system, idle, iowait, irq, softirq, steal int64
}

func readCPUSample() (*cpuSample, error) {
	lines, err := readProcFile("/proc/stat")
	if err != nil {
		return nil, err
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 8 {
				continue
			}
			return &cpuSample{
				user:    parseInt(fields[1]),
				nice:    parseInt(fields[2]),
				system:  parseInt(fields[3]),
				idle:    parseInt(fields[4]),
				iowait:  parseInt(fields[5]),
				irq:     parseInt(fields[6]),
				softirq: parseInt(fields[7]),
			}, nil
		}
	}
	return nil, fmt.Errorf("cpu line not found")
}

func (s *cpuSample) total() int64 {
	return s.user + s.nice + s.system + s.idle + s.iowait + s.irq + s.softirq
}

func (s *cpuSample) idleTotal() int64 {
	return s.idle + s.iowait
}

func cpuPercent(prev, curr *cpuSample) float64 {
	prevTotal := prev.total()
	currTotal := curr.total()
	prevIdle := prev.idleTotal()
	currIdle := curr.idleTotal()
	totalDelta := currTotal - prevTotal
	idleDelta := currIdle - prevIdle
	if totalDelta == 0 {
		return 0
	}
	return math.Round((1-float64(idleDelta)/float64(totalDelta))*100*10) / 10
}

// ====== 内存 ======
func readMemory() (total, used int64, err error) {
	lines, err := readProcFile("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	var memTotal, memFree, buffers, cached, sReclaimable int64
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val := parseInt(fields[1]) * 1024
		switch fields[0] {
		case "MemTotal:":
			memTotal = val
		case "MemFree:":
			memFree = val
		case "Buffers:":
			buffers = val
		case "Cached:":
			cached = val
		case "SReclaimable:":
			sReclaimable = val
		}
	}
	used = memTotal - memFree - buffers - cached - sReclaimable
	if used < 0 {
		used = 0
	}
	return memTotal, used, nil
}

// ====== 磁盘 ======
func readDisk(path string) (total, used int64, err error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, err
	}
	total = int64(stat.Blocks) * int64(stat.Bsize)
	available := int64(stat.Bavail) * int64(stat.Bsize)
	used = total - available
	return total, used, nil
}

// ====== 网络流量 ======
func readNetDev() (map[string][2]int64, error) {
	lines, err := readProcFile("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	result := make(map[string][2]int64)
	for _, line := range lines {
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		rx := parseInt(fields[0])
		tx := parseInt(fields[8])
		result[iface] = [2]int64{rx, tx}
	}
	return result, nil
}

// isPhysicalInterface 过滤虚拟网卡（docker、libvirt、隧道等），只保留物理网卡
func isPhysicalInterface(name string) bool {
	virtualPrefixes := []string{"lo", "docker", "virbr", "veth", "br-", "tun", "tap", "vnet"}
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	return true
}

func getActiveInterfaces() []string {
	data, _ := readNetDev()
	var out []string
	for name := range data {
		if isPhysicalInterface(name) {
			out = append(out, name)
		}
	}
	return out
}

func calcDelta(current, last int64) (delta int64, reset bool) {
	if last < 0 {
		return current, false
	}
	if current < last {
		return current, true
	}
	return current - last, false
}

// ====== 数据库 ======
func initDB() error {
	var err error
	os.MkdirAll(filepath.Dir(DBPath), 0755)
	db, err = sql.Open("sqlite", DBPath+"?_journal_mode=WAL&_synchronous=NORMAL")
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)

	schema := `
	PRAGMA journal_mode=WAL;
	PRAGMA synchronous=NORMAL;
	PRAGMA busy_timeout=5000;

	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		created_at TEXT DEFAULT (datetime('now'))
	);

	CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		created_at TEXT DEFAULT (datetime('now')),
		expires_at TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS traffic_state (
		iface TEXT PRIMARY KEY,
		last_rx INTEGER NOT NULL DEFAULT 0,
		last_tx INTEGER NOT NULL DEFAULT 0,
		last_update TEXT
	);

	CREATE TABLE IF NOT EXISTS traffic_monthly (
		month_key TEXT NOT NULL,
		iface TEXT NOT NULL,
		rx_delta INTEGER NOT NULL DEFAULT 0,
		tx_delta INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (month_key, iface)
	);

	CREATE TABLE IF NOT EXISTS traffic_daily (
		date TEXT NOT NULL,
		iface TEXT NOT NULL,
		rx_delta INTEGER NOT NULL DEFAULT 0,
		tx_delta INTEGER NOT NULL DEFAULT 0,
		month_key TEXT NOT NULL,
		PRIMARY KEY (date, iface)
	);

	CREATE TABLE IF NOT EXISTS traffic_raw (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		iface TEXT NOT NULL,
		rx_bytes INTEGER NOT NULL,
		tx_bytes INTEGER NOT NULL,
		rx_delta INTEGER NOT NULL DEFAULT 0,
		tx_delta INTEGER NOT NULL DEFAULT 0,
		month_key TEXT NOT NULL,
		reset_detected INTEGER NOT NULL DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_traffic_raw_month ON traffic_raw(month_key, timestamp);
	CREATE INDEX IF NOT EXISTS idx_traffic_daily_month ON traffic_daily(month_key);
	CREATE INDEX IF NOT EXISTS idx_traffic_monthly_key ON traffic_monthly(month_key);
	`
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	return nil
}

func ensureDefaultUser(password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT OR IGNORE INTO users (username, password_hash) VALUES ('admin', ?)`, string(hash))
	return err
}

// ====== 会话管理 ======
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func createSession(userID int64) (string, error) {
	token, err := generateToken()
	if err != nil {
		return "", err
	}
	expires := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	_, err = db.Exec(`INSERT OR REPLACE INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)`,
		token, userID, expires)
	return token, err
}

func validateSession(r *http.Request) bool {
	cookie, err := r.Cookie("probe_session")
	if err != nil {
		return false
	}
	var expiresAt string
	err = db.QueryRow(`SELECT expires_at FROM sessions WHERE token = ?`, cookie.Value).Scan(&expiresAt)
	if err != nil {
		return false
	}
	t, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || time.Now().UTC().After(t) {
		db.Exec(`DELETE FROM sessions WHERE token = ?`, cookie.Value)
		return false
	}
	return true
}

func deleteSession(token string) {
	db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validateSession(r) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(w, `{"error":"未登录"}`, http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// ====== 系统采集 ======
func collectSystemStats() SysStats {
	var s SysStats
	prev, err := readCPUSample()
	if err == nil {
		time.Sleep(500 * time.Millisecond)
		curr, err2 := readCPUSample()
		if err2 == nil {
			s.CPU = cpuPercent(prev, curr)
		}
	}
	total, used, err := readMemory()
	if err == nil {
		s.MemTotal = total
		s.MemUsed = used
	}
	dTotal, dUsed, err := readDisk("/")
	if err == nil {
		s.DiskTotal = dTotal
		s.DiskUsed = dUsed
	}
	return s
}

func collectTraffic() {
	now := time.Now()
	today := now.Format("2006-01-02")
	monthKey := now.Format("2006-01")

	netDev, err := readNetDev()
	if err != nil {
		log.Printf("ERROR readNetDev: %v", err)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("ERROR begin tx: %v", err)
		return
	}
	defer tx.Rollback()

	for iface, counters := range netDev {
		if !isPhysicalInterface(iface) {
			continue
		}
		rx, txBytes := counters[0], counters[1]

		var lastRx, lastTx int64
		err := tx.QueryRow(`SELECT last_rx, last_tx FROM traffic_state WHERE iface = ?`, iface).
			Scan(&lastRx, &lastTx)
		if err == sql.ErrNoRows {
			lastRx, lastTx = -1, -1
		} else if err != nil {
			log.Printf("ERROR query state %s: %v", iface, err)
			continue
		}

		rxDelta, rxReset := calcDelta(rx, lastRx)
		txDelta, txReset := calcDelta(txBytes, lastTx)
		resetFlag := 0
		if rxReset || txReset {
			resetFlag = 1
			log.Printf("检测到计数器回绕 %s (rx: %d->%d, tx: %d->%d)", iface, lastRx, rx, lastTx, txBytes)
		}

		nowStr := now.UTC().Format(time.RFC3339)
		_, err = tx.Exec(`INSERT INTO traffic_raw (timestamp, iface, rx_bytes, tx_bytes, rx_delta, tx_delta, month_key, reset_detected)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			nowStr, iface, rx, txBytes, rxDelta, txDelta, monthKey, resetFlag)
		if err != nil {
			log.Printf("ERROR insert raw %s: %v", iface, err)
			continue
		}

		// 每日聚合（按 date 分区，每日自然清零）
		_, err = tx.Exec(`INSERT INTO traffic_daily (date, iface, rx_delta, tx_delta, month_key)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(date, iface) DO UPDATE SET
			rx_delta = rx_delta + excluded.rx_delta,
			tx_delta = tx_delta + excluded.tx_delta,
			month_key = excluded.month_key`,
			today, iface, rxDelta, txDelta, monthKey)
		if err != nil {
			log.Printf("ERROR upsert daily %s: %v", iface, err)
			continue
		}

		// 每月聚合（按 month_key 分区，每月1号自然清零）
		_, err = tx.Exec(`INSERT INTO traffic_monthly (month_key, iface, rx_delta, tx_delta)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(month_key, iface) DO UPDATE SET
			rx_delta = rx_delta + excluded.rx_delta,
			tx_delta = tx_delta + excluded.tx_delta`,
			monthKey, iface, rxDelta, txDelta)
		if err != nil {
			log.Printf("ERROR upsert monthly %s: %v", iface, err)
			continue
		}

		_, err = tx.Exec(`INSERT OR REPLACE INTO traffic_state (iface, last_rx, last_tx, last_update)
			VALUES (?, ?, ?, ?)`,
			iface, rx, txBytes, nowStr)
		if err != nil {
			log.Printf("ERROR upsert state %s: %v", iface, err)
			continue
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("ERROR commit traffic: %v", err)
	}
}

func startCollector() {
	latest = collectSystemStats()
	collectTraffic()

	go func() {
		ticker := time.NewTicker(PollInterval)
		defer ticker.Stop()
		for range ticker.C {
			s := collectSystemStats()
			statsMu.Lock()
			latest = s
			statsMu.Unlock()
			collectTraffic()
		}
	}()
}

// ====== 页面处理器 ======
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(loginHTML))
		return
	}
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var id int64
		var hash string
		err := db.QueryRow(`SELECT id, password_hash FROM users WHERE username = ?`, username).Scan(&id, &hash)
		if err != nil {
			http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
			http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
			return
		}
		token, err := createSession(id)
		if err != nil {
			http.Error(w, "会话错误", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "probe_session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   86400,
			SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Error(w, "不允许的请求方法", http.StatusMethodNotAllowed)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("probe_session"); err == nil {
		deleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "probe_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	data := buildDashboardData()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardTmpl.Execute(w, data); err != nil {
		log.Printf("模板错误: %v", err)
	}
}

func handlePasswordPage(w http.ResponseWriter, r *http.Request) {
	errMsg := ""
	if r.Method == "POST" {
		oldPwd := r.FormValue("old_password")
		newPwd := r.FormValue("new_password")
		newPwd2 := r.FormValue("new_password2")

		if newPwd != newPwd2 {
			errMsg = "两次输入的新密码不一致"
		} else if len(newPwd) < 4 {
			errMsg = "新密码至少4个字符"
		} else {
			// verify old password
			var id int64
			var hash string
			cookie, _ := r.Cookie("probe_session")
			db.QueryRow(`SELECT u.id, u.password_hash FROM users u
				JOIN sessions s ON s.user_id = u.id WHERE s.token = ?`, cookie.Value).Scan(&id, &hash)
			if bcrypt.CompareHashAndPassword([]byte(hash), []byte(oldPwd)) != nil {
				errMsg = "原密码错误"
			} else {
				newHash, _ := bcrypt.GenerateFromPassword([]byte(newPwd), BcryptCost)
				db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, string(newHash), id)
				// clear all sessions for this user (force re-login)
				db.Exec(`DELETE FROM sessions WHERE user_id = ?`, id)
				http.Redirect(w, r, "/login?changed=1", http.StatusSeeOther)
				return
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl, _ := template.New("password").Parse(passwordHTML)
	tmpl.Execute(w, map[string]string{"Error": errMsg})
}

// ====== API 处理器 ======
func handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	statsMu.Lock()
	s := latest
	statsMu.Unlock()

	monthKey := time.Now().Format("2006-01")
	var monthRx, monthTx int64
	db.QueryRow(`SELECT COALESCE(SUM(rx_delta),0), COALESCE(SUM(tx_delta),0) FROM traffic_monthly WHERE month_key = ?`, monthKey).
		Scan(&monthRx, &monthTx)

	resp := map[string]interface{}{
		"cpu_percent":      s.CPU,
		"mem_used_bytes":   s.MemUsed,
		"mem_total_bytes":  s.MemTotal,
		"disk_used_bytes":  s.DiskUsed,
		"disk_total_bytes": s.DiskTotal,
		"traffic_rx_bytes": monthRx,
		"traffic_tx_bytes": monthTx,
		"month_key":        monthKey,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleAPIDaily(w http.ResponseWriter, r *http.Request) {
	monthKey := r.URL.Query().Get("month")
	if monthKey == "" {
		monthKey = time.Now().Format("2006-01")
	}
	rows, err := db.Query(`SELECT date, COALESCE(SUM(rx_delta),0), COALESCE(SUM(tx_delta),0)
		FROM traffic_daily WHERE month_key = ? GROUP BY date ORDER BY date`, monthKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var result []DailyTraffic
	for rows.Next() {
		var d DailyTraffic
		if err := rows.Scan(&d.Date, &d.RxDelta, &d.TxDelta); err != nil {
			continue
		}
		result = append(result, d)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleAPIMonthlyHistory(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`SELECT month_key, COALESCE(SUM(rx_delta),0), COALESCE(SUM(tx_delta),0)
		FROM traffic_monthly GROUP BY month_key ORDER BY month_key DESC LIMIT 12`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var result []MonthlyTraffic
	for rows.Next() {
		var m MonthlyTraffic
		if err := rows.Scan(&m.MonthKey, &m.RxDelta, &m.TxDelta); err != nil {
			continue
		}
		result = append(result, m)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleAPIChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"仅支持POST"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"JSON解析失败"}`, http.StatusBadRequest)
		return
	}
	if len(req.NewPassword) < 4 {
		http.Error(w, `{"error":"新密码至少4个字符"}`, http.StatusBadRequest)
		return
	}

	cookie, _ := r.Cookie("probe_session")
	var id int64
	var hash string
	err := db.QueryRow(`SELECT u.id, u.password_hash FROM users u
		JOIN sessions s ON s.user_id = u.id WHERE s.token = ?`, cookie.Value).Scan(&id, &hash)
	if err != nil {
		http.Error(w, `{"error":"会话无效"}`, http.StatusUnauthorized)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)) != nil {
		http.Error(w, `{"error":"原密码错误"}`, http.StatusForbidden)
		return
	}

	newHash, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), BcryptCost)
	db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, string(newHash), id)
	db.Exec(`DELETE FROM sessions WHERE user_id = ?`, id) // 踢掉所有旧会话

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "密码已修改，请重新登录"})
}

// ====== 数据组装 ======
func buildDashboardData() DashboardData {
	statsMu.Lock()
	s := latest
	statsMu.Unlock()

	monthKey := time.Now().Format("2006-01")
	today := time.Now().Format("2006-01-02")

	var monthRx, monthTx, todayRx, todayTx int64
	db.QueryRow(`SELECT COALESCE(SUM(rx_delta),0), COALESCE(SUM(tx_delta),0) FROM traffic_monthly WHERE month_key = ?`, monthKey).
		Scan(&monthRx, &monthTx)
	db.QueryRow(`SELECT COALESCE(SUM(rx_delta),0), COALESCE(SUM(tx_delta),0) FROM traffic_daily WHERE date = ?`, today).
		Scan(&todayRx, &todayTx)

	// 当月每日流量
	dailyRows, _ := db.Query(`SELECT date, COALESCE(SUM(rx_delta),0), COALESCE(SUM(tx_delta),0)
		FROM traffic_daily WHERE month_key = ? GROUP BY date ORDER BY date`, monthKey)
	var daily []DailyTraffic
	if dailyRows != nil {
		defer dailyRows.Close()
		for dailyRows.Next() {
			var d DailyTraffic
			if dailyRows.Scan(&d.Date, &d.RxDelta, &d.TxDelta) == nil {
				daily = append(daily, d)
			}
		}
	}

	// 运行时间
	uptimeBytes, _ := os.ReadFile("/proc/uptime")
	uptime := "N/A"
	if len(uptimeBytes) > 0 {
		parts := strings.Fields(string(uptimeBytes))
		if len(parts) > 0 {
			secs, _ := strconv.ParseFloat(parts[0], 64)
			d := time.Duration(secs) * time.Second
			days := int(d.Hours()) / 24
			hours := int(d.Hours()) % 24
			minutes := int(d.Minutes()) % 60
			uptime = fmt.Sprintf("%d天 %d小时 %d分钟", days, hours, minutes)
		}
	}

	// 月度历史
	histRows, _ := db.Query(`SELECT month_key, COALESCE(SUM(rx_delta),0), COALESCE(SUM(tx_delta),0)
		FROM traffic_monthly GROUP BY month_key ORDER BY month_key DESC LIMIT 12`)
	var hist []MonthlyTraffic
	if histRows != nil {
		defer histRows.Close()
		for histRows.Next() {
			var m MonthlyTraffic
			if histRows.Scan(&m.MonthKey, &m.RxDelta, &m.TxDelta) == nil {
				hist = append(hist, m)
			}
		}
	}

	var lastCollect string
	db.QueryRow(`SELECT COALESCE(MAX(timestamp), '暂无数据') FROM traffic_raw`).Scan(&lastCollect)

	return DashboardData{
		Stats:           s,
		MonthRx:         monthRx,
		MonthTx:         monthTx,
		TodayRx:         todayRx,
		TodayTx:         todayTx,
		MonthKey:        monthKey,
		DailyTraffic:    daily,
		MonthlyHistory:  hist,
		Interfaces:      getActiveInterfaces(),
		Uptime:          uptime,
		LastCollectTime: lastCollect,
	}
}

// ====== 工具函数 ======
func parseInt(s string) int64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

func formatBytes(n int64) string {
	if n < 0 {
		return "0 B"
	}
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	var i int
	f := float64(n)
	for i = 0; f >= 1024 && i < len(units)-1; i++ {
		f /= 1024
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", f, units[i])
	}
	return fmt.Sprintf("%.2f %s", f, units[i])
}

// ====== 模板初始化 ======
var dashboardTmpl *template.Template

func init() {
	dashboardTmpl = template.Must(template.New("dashboard").Funcs(template.FuncMap{
		"formatBytes": func(n int64) string { return formatBytes(n) },
		"percentOf": func(part, total int64) string {
			if total == 0 {
				return "0"
			}
			p := float64(part) / float64(total) * 100
			if p > 100 {
				p = 100
			}
			return fmt.Sprintf("%.1f", p)
		},
		"add": func(a, b int64) int64 { return a + b },
	}).Parse(dashboardHTML))
}

// ====== 主入口 ======
func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if err := initDB(); err != nil {
		log.Fatalf("数据库初始化失败: %v", err)
	}
	defer db.Close()

	password := os.Getenv("PROBE_PASSWORD")
	if password == "" {
		password = "admin"
	}
	if err := ensureDefaultUser(password); err != nil {
		log.Fatalf("用户初始化失败: %v", err)
	}

	startCollector()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", handleLogin)
	mux.HandleFunc("POST /login", handleLogin)
	mux.HandleFunc("GET /logout", handleLogout)
	mux.HandleFunc("GET /", requireAuth(handleDashboard))
	mux.HandleFunc("GET /password", requireAuth(handlePasswordPage))
	mux.HandleFunc("POST /password", requireAuth(handlePasswordPage))
	mux.HandleFunc("GET /api/status", requireAuth(handleAPIStatus))
	mux.HandleFunc("GET /api/traffic/daily", requireAuth(handleAPIDaily))
	mux.HandleFunc("GET /api/traffic/history", requireAuth(handleAPIMonthlyHistory))
	mux.HandleFunc("POST /api/change-password", requireAuth(handleAPIChangePassword))
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	srv := &http.Server{
		Addr:         ListenAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("probe 启动在 %s", ListenAddr)
	log.Printf("默认账号: admin / %s", password)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}

// ====== 内嵌 HTML 模板 ======

const loginHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>probe · 系统监控</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Microsoft YaHei','PingFang SC',sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{background:#1e293b;border-radius:12px;padding:40px;width:100%;max-width:400px;box-shadow:0 25px 50px rgba(0,0,0,0.4);border:1px solid #334155}
.box h1{text-align:center;margin-bottom:4px;font-size:28px;color:#38bdf8}
.box .sub{text-align:center;color:#94a3b8;margin-bottom:24px;font-size:14px}
.fg{margin-bottom:16px}
.fg label{display:block;margin-bottom:6px;color:#94a3b8;font-size:14px}
.fg input{width:100%;padding:10px 14px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:15px;outline:none;transition:border-color .2s}
.fg input:focus{border-color:#38bdf8}
.btn{width:100%;padding:12px;background:#38bdf8;color:#0f172a;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;transition:background .2s}
.btn:hover{background:#7dd3fc}
.msg{text-align:center;margin-top:12px;font-size:14px}
.msg.ok{color:#34d399}
.msg.err{color:#f87171}
</style>
</head>
<body>
<div class="box">
<h1>&#128225; probe</h1>
<div class="sub">系统资源监控面板</div>
<form method="POST">
<div class="fg"><label>用户名</label><input name="username" type="text" required autofocus></div>
<div class="fg"><label>密码</label><input name="password" type="password" required></div>
<button class="btn" type="submit">登 录</button>
</form>
</div>
</body>
</html>`

const passwordHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>修改密码 · probe</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Microsoft YaHei','PingFang SC',sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{background:#1e293b;border-radius:12px;padding:40px;width:100%;max-width:420px;box-shadow:0 25px 50px rgba(0,0,0,0.4);border:1px solid #334155}
.box h2{text-align:center;margin-bottom:20px;color:#38bdf8;font-size:22px}
.fg{margin-bottom:16px}
.fg label{display:block;margin-bottom:6px;color:#94a3b8;font-size:14px}
.fg input{width:100%;padding:10px 14px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:15px;outline:none}
.fg input:focus{border-color:#38bdf8}
.btn{width:100%;padding:12px;background:#38bdf8;color:#0f172a;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;margin-bottom:12px}
.btn:hover{background:#7dd3fc}
.back{display:block;text-align:center;color:#94a3b8;text-decoration:none;font-size:14px}
.back:hover{color:#38bdf8}
.err{color:#f87171;text-align:center;margin-bottom:16px;font-size:14px}
</style>
</head>
<body>
<div class="box">
<h2>&#128274; 修改密码</h2>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<form method="POST">
<div class="fg"><label>原密码</label><input name="old_password" type="password" required></div>
<div class="fg"><label>新密码</label><input name="new_password" type="password" required minlength="4"></div>
<div class="fg"><label>确认新密码</label><input name="new_password2" type="password" required minlength="4"></div>
<button class="btn" type="submit">确认修改</button>
</form>
<a class="back" href="/">&larr; 返回仪表盘</a>
</div>
</body>
</html>`

const dashboardHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>probe · {{.MonthKey}} 系统监控</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js">
</script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Microsoft YaHei','PingFang SC',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
.header{background:#1e293b;border-bottom:1px solid #334155;padding:12px 24px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
.header h1{font-size:20px;color:#38bdf8}
.header .nav{display:flex;align-items:center;gap:16px;font-size:14px}
.header .nav a{color:#94a3b8;text-decoration:none}
.header .nav a:hover{color:#38bdf8}
.header .nav a.logout{color:#f87171}
.uptime{color:#64748b;font-size:13px}
.container{padding:20px 24px;max-width:1400px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;margin-bottom:20px}
.card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:18px}
.card .label{color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px}
.card .value{font-size:26px;font-weight:700}
.card .sub{color:#64748b;font-size:12px;margin-top:4px}
.card .bar-wrap{background:#0f172a;border-radius:6px;height:6px;margin-top:8px;overflow:hidden}
.card .bar-fill{height:100%;border-radius:6px;transition:width .5s}
.cpu .value{color:#38bdf8} .cpu .bar-fill{background:#38bdf8}
.mem .value{color:#a78bfa} .mem .bar-fill{background:#a78bfa}
.disk .value{color:#fbbf24} .disk .bar-fill{background:#fbbf24}
.traffic .value{color:#34d399}
.traffic-cols{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:6px}
.tc .lbl{font-size:11px;color:#64748b}
.tc .val{font-size:16px;font-weight:600;font-variant-numeric:tabular-nums}
.panel{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:18px;margin-bottom:20px}
.panel h3{color:#94a3b8;font-size:14px;margin-bottom:12px}
canvas{max-height:320px}
table{width:100%;border-collapse:collapse;font-size:14px;margin-top:8px}
table th{text-align:left;color:#94a3b8;padding:8px 12px;border-bottom:1px solid #334155;font-weight:500;font-size:12px;text-transform:uppercase}
table td{padding:8px 12px;border-bottom:1px solid #1e293b;font-variant-numeric:tabular-nums}
table tr:hover td{background:rgba(56,189,248,0.04)}
.tags{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}
.tag{background:rgba(56,189,248,0.12);color:#38bdf8;padding:2px 10px;border-radius:10px;font-size:11px}
.footer{text-align:center;color:#475569;font-size:12px;padding:10px 0;border-top:1px solid #1e293b}
.traffic-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:8px}
.traffic-item .label{font-size:11px;color:#64748b}
.traffic-item .val{font-size:18px;font-weight:600;font-variant-numeric:tabular-nums}
</style>
</head>
<body>
<div class="header">
<h1>&#128225; probe</h1>
<div class="nav">
<span class="uptime">&#9202; 运行 {{.Uptime}}</span>
<a href="/password">修改密码</a>
<a class="logout" href="/logout">退出登录</a>
</div>
</div>
<div class="container">

<!-- 系统状态卡片 -->
<div class="cards">
<div class="card cpu">
<div class="label">CPU 使用率</div>
<div class="value">{{printf "%.1f" .Stats.CPU}}%</div>
<div class="bar-wrap"><div class="bar-fill" style="width:{{printf "%.1f" .Stats.CPU}}%"></div></div>
</div>
<div class="card mem">
<div class="label">内存</div>
<div class="value">{{.Stats.MemUsed | formatBytes}} / {{.Stats.MemTotal | formatBytes}}</div>
<div class="sub">已使用 {{.Stats.MemUsed | percentOf .Stats.MemTotal}}%</div>
<div class="bar-wrap"><div class="bar-fill" style="width:{{.Stats.MemUsed | percentOf .Stats.MemTotal}}%"></div></div>
</div>
<div class="card disk">
<div class="label">磁盘</div>
<div class="value">{{.Stats.DiskUsed | formatBytes}} / {{.Stats.DiskTotal | formatBytes}}</div>
<div class="sub">已使用 {{.Stats.DiskUsed | percentOf .Stats.DiskTotal}}%</div>
<div class="bar-wrap"><div class="bar-fill" style="width:{{.Stats.DiskUsed | percentOf .Stats.DiskTotal}}%"></div></div>
</div>
<div class="card traffic">
<div class="label">本月流量 ({{.MonthKey}})</div>
<div class="traffic-grid">
<div><div class="label" style="font-size:11px;color:#64748b">下载</div><div class="val" style="color:#38bdf8">{{.MonthRx | formatBytes}}</div></div>
<div><div class="label" style="font-size:11px;color:#64748b">上传</div><div class="val" style="color:#a78bfa">{{.MonthTx | formatBytes}}</div></div>
</div>
<div class="traffic-grid" style="margin-top:8px">
<div><div class="label" style="font-size:11px;color:#64748b">今日下载</div><div class="val" style="font-size:14px;color:#94a3b8">{{.TodayRx | formatBytes}}</div></div>
<div><div class="label" style="font-size:11px;color:#64748b">今日上传</div><div class="val" style="font-size:14px;color:#94a3b8">{{.TodayTx | formatBytes}}</div></div>
</div>
<div class="sub" style="margin-top:6px">本月合计: {{add .MonthRx .MonthTx | formatBytes}} &middot; 每月1号自动清零</div>
</div>
</div>

<!-- 两张流量图表并排 -->
<div class="charts" style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px">
<div class="panel">
<h3>&#128200; 本月每日流量 ({{.MonthKey}})</h3>
<div class="tags">
{{range .Interfaces}}<span class="tag">{{.}}</span>{{end}}
</div>
<canvas id="dailyChart"></canvas>
</div>
<div class="panel">
<h3>&#128201; 历史月度流量</h3>
<canvas id="monthlyChart"></canvas>
</div>
</div>

<!-- 每日 + 每月明细表 -->
<div class="charts" style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px">
<div class="panel">
<h3>&#128204; 每日流量明细</h3>
<table>
<thead><tr><th>日期</th><th>下载</th><th>上传</th><th>合计</th></tr></thead>
<tbody>
{{range .DailyTraffic}}
<tr><td>{{.Date}}</td><td>{{.RxDelta | formatBytes}}</td><td>{{.TxDelta | formatBytes}}</td><td>{{add .RxDelta .TxDelta | formatBytes}}</td></tr>
{{else}}
<tr><td colspan="4" style="color:#64748b;text-align:center">正在采集数据...</td></tr>
{{end}}
</tbody>
</table>
</div>
<div class="panel">
<h3>&#128202; 月度流量统计</h3>
<table>
<thead><tr><th>月份</th><th>下载</th><th>上传</th><th>合计</th></tr></thead>
<tbody>
{{range .MonthlyHistory}}
<tr><td>{{.MonthKey}}</td><td>{{.RxDelta | formatBytes}}</td><td>{{.TxDelta | formatBytes}}</td><td>{{add .RxDelta .TxDelta | formatBytes}}</td></tr>
{{else}}
<tr><td colspan="4" style="color:#64748b;text-align:center">正在采集数据...</td></tr>
{{end}}
</tbody>
</table>
</div>
</div>

<div class="footer">
最近采集: {{.LastCollectTime}} &middot; 数据每10秒更新 &middot; probe v1.1
</div>
</div>

<script>
// 本月每日流量
const dailyData = [{{range .DailyTraffic}}{date:"{{.Date}}",rx:{{.RxDelta}},tx:{{.TxDelta}}},{{end}}];
(function(){
	var ctx = document.getElementById('dailyChart');
	if(!ctx||dailyData.length===0)return;
	var labels = dailyData.map(function(d){return d.date.slice(-5)});
	var rx = dailyData.map(function(d){return d.rx});
	var tx = dailyData.map(function(d){return d.tx});
	new Chart(ctx,{type:'bar',data:{labels:labels,datasets:[
		{label:'下载',data:rx,backgroundColor:'#38bdf8',borderRadius:4},
		{label:'上传',data:tx,backgroundColor:'#a78bfa',borderRadius:4}
	]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#94a3b8'}}},
	scales:{x:{ticks:{color:'#64748b'}},y:{ticks:{color:'#64748b',callback:function(v){return fmtB(v)}}}}}});
})();

// 历史月度流量
const monthlyData = [{{range .MonthlyHistory}}{month:"{{.MonthKey}}",rx:{{.RxDelta}},tx:{{.TxDelta}}},{{end}}];
(function(){
	var ctx = document.getElementById('monthlyChart');
	if(!ctx||monthlyData.length===0)return;
	var labels = monthlyData.map(function(d){return d.month}).reverse();
	var rx = monthlyData.map(function(d){return d.rx}).reverse();
	var tx = monthlyData.map(function(d){return d.tx}).reverse();
	new Chart(ctx,{type:'bar',data:{labels:labels,datasets:[
		{label:'下载',data:rx,backgroundColor:'#38bdf8',borderRadius:4},
		{label:'上传',data:tx,backgroundColor:'#a78bfa',borderRadius:4}
	]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#94a3b8'}}},
	scales:{x:{ticks:{color:'#64748b'}},y:{ticks:{color:'#64748b',callback:function(v){return fmtB(v)}}}}}});
})();

function fmtB(n){if(!n||n<0)return'0 B';var u=['B','KB','MB','GB','TB'];var i=0,f=n;while(f>=1024&&i<u.length-1){f/=1024;i++}return i===0?Math.round(f)+' '+u[i]:f.toFixed(2)+' '+u[i]}
</script>
</body>
</html>`
