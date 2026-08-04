package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	openhttp "github.com/TheGrimmChester/open-http-go"
	opentenant "github.com/TheGrimmChester/open-tenant-go"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

func escapeSQL(s string) string {
	return opentenant.EscapeSQL(s)
}

func getString(row map[string]interface{}, key string) string {
	if row == nil {
		return ""
	}
	v, ok := row[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func getFloat64(row map[string]interface{}, key string) float64 {
	if row == nil {
		return 0
	}
	v, ok := row[key]
	if !ok || v == nil {
		return 0
	}
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case json.Number:
		f, _ := t.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		return f
	default:
		return 0
	}
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func truncateStr(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max]
}

func atoiDefault(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

func clampInt(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// loadID mirrors the Perf lab helper used by SCM contexts/jobs.
func loadID(prefix string, parts ...string) string {
	h := sha1.New()
	h.Write([]byte(prefix))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return prefix + "-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// Federation write-locality is Agent-only; Orchestrator always allows writes.
func enforceWriteLocalityHTTP(w http.ResponseWriter, r *http.Request, org, proj string) bool {
	_ = w
	_ = r
	_ = org
	_ = proj
	return true
}

func corsMiddleware(next http.Handler) http.Handler {
	return openhttp.MiddlewareCORS(next)
}

func nowUTC() time.Time { return time.Now().UTC() }

func nz(s, d string) string {
	if strings.TrimSpace(s) != "" {
		return s
	}
	return d
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
