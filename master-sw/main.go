package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const DB_PATH = "/etc/wireguard/master-sw/master.db"

type Worker struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	ApiKey     string `json:"api_key"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	CIDR       string `json:"cidr"`
}

func main() {
	if err := os.MkdirAll("/etc/wireguard/master-sw", 0755); err != nil {
		log.Fatalf("mkdir: %v", err)
	}

	db, err := sql.Open("sqlite3", DB_PATH)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS workers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT, ip TEXT, port INTEGER, api_key TEXT, private_key TEXT, public_key TEXT, cidr TEXT
	)`); err != nil {
		log.Fatalf("create table: %v", err)
	}
	log.Printf("MASTER: DB initialized at %s", DB_PATH)
	log.Printf("MASTER: web UI served from /etc/wireguard/master-sw/web")

	// API to create/list workers
	http.HandleFunc("/api/workers", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("MASTER: incoming %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		switch r.Method {
		case http.MethodPost:
			var req Worker
			b, _ := io.ReadAll(r.Body)
			log.Printf("MASTER: POST /api/workers body=%s", string(b))
			if err := json.Unmarshal(b, &req); err != nil {
				log.Printf("MASTER: invalid json: %v", err)
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			// generate wg keys via 'wg' if available
			priv, pub, err := generateKeyPair()
			if err != nil {
				log.Printf("MASTER: key gen failed: %v", err)
				// allow provided keys in request
			} else {
				log.Printf("MASTER: generated key (public)=%s private=(masked)", pub)
				req.PrivateKey = priv
				req.PublicKey = pub
			}
			// allocate address
			addr, err := allocateAddress(db)
			if err != nil {
				log.Printf("MASTER: allocate address failed: %v", err)
				http.Error(w, "address allocation failed", http.StatusInternalServerError)
				return
			}
			req.CIDR = addr
			res, err := db.Exec("INSERT INTO workers(name,ip,port,api_key,private_key,public_key,cidr) VALUES(?,?,?,?,?,?,?)",
				req.Name, req.IP, req.Port, req.ApiKey, req.PrivateKey, req.PublicKey, req.CIDR)
			if err != nil {
				log.Printf("MASTER: db insert failed: %v", err)
				http.Error(w, "db insert failed", http.StatusInternalServerError)
				return
			}
			id, _ := res.LastInsertId()
			log.Printf("MASTER: worker created id=%d name=%s ip=%s:%d cidr=%s pub=%s", id, req.Name, req.IP, req.Port, req.CIDR, req.PublicKey)
			// setup full mesh connections; do not block
			go setupWorkerMesh(db, &req)
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, "created id=%d\n", id)
		case http.MethodGet:
			rows, err := db.Query("SELECT id,name,ip,port,api_key,private_key,public_key,cidr FROM workers")
			if err != nil {
				log.Printf("MASTER: db list failed: %v", err)
				http.Error(w, "db list failed", http.StatusInternalServerError)
				return
			}
			defer rows.Close()
			var out []Worker
			for rows.Next() {
				var wkr Worker
				rows.Scan(&wkr.ID, &wkr.Name, &wkr.IP, &wkr.Port, &wkr.ApiKey, &wkr.PrivateKey, &wkr.PublicKey, &wkr.CIDR)
				out = append(out, wkr)
			}
			log.Printf("MASTER: returning %d workers", len(out))
			json.NewEncoder(w).Encode(out)
		default:
			log.Printf("MASTER: method not allowed: %s", r.Method)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Status proxy for a worker (called by frontend)
	http.HandleFunc("/api/workers/status", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("MASTER: status request %s from %s", r.URL.String(), r.RemoteAddr)
		idStr := r.URL.Query().Get("id")
		if idStr == "" {
			log.Printf("MASTER: missing id in status request")
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			log.Printf("MASTER: invalid id: %v", err)
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}
		row := db.QueryRow("SELECT id,name,ip,port,api_key,private_key,public_key,cidr FROM workers WHERE id = ?", id)
		var wkr Worker
		if err := row.Scan(&wkr.ID, &wkr.Name, &wkr.IP, &wkr.Port, &wkr.ApiKey, &wkr.PrivateKey, &wkr.PublicKey, &wkr.CIDR); err != nil {
			log.Printf("MASTER: worker not found id=%d", id)
			http.Error(w, "worker not found", http.StatusNotFound)
			return
		}
		url := fmt.Sprintf("http://%s:%d/api/wg/status", wkr.IP, wkr.Port)
		log.Printf("MASTER: proxying status request to %s", url)
		client := &http.Client{Timeout: 5 * time.Second}
		req2, _ := http.NewRequest("GET", url, nil)
		req2.Header.Set("X-API-Key", wkr.ApiKey)
		resp, err := client.Do(req2)
		if err != nil {
			log.Printf("MASTER: worker status request failed: %v", err)
			http.Error(w, fmt.Sprintf("request failed: %v", err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		log.Printf("MASTER: worker status response status=%d len=%d", resp.StatusCode, len(body))
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
	})

	// Serve web UI
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("/etc/wireguard/master-sw/web/static"))))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, "/etc/wireguard/master-sw/web/index.html")
	})

	addr := ":8080"
	log.Printf("master listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

const MASTER_NETWORK = "10.100.0.0/22"
const WG_PORT = 51820

func generateKeyPair() (priv, pub string, err error) {
	// try wg genkey + wg pubkey
	privCmd := exec.Command("wg", "genkey")
	privOut, err := privCmd.Output()
	if err != nil {
		return "", "", err
	}
	pubCmd := exec.Command("wg", "pubkey")
	pubCmd.Stdin = bytes.NewReader(privOut)
	pubOut, err := pubCmd.Output()
	if err != nil {
		return "", "", err
	}
	return string(bytes.TrimSpace(privOut)), string(bytes.TrimSpace(pubOut)), nil
}

// allocateAddress assigns the next free IP in MASTER_NETWORK as /32 (e.g. 10.100.0.2/32)
func allocateAddress(db *sql.DB) (string, error) {
	_, ipnet, err := net.ParseCIDR(MASTER_NETWORK)
	if err != nil {
		return "", err
	}
	// collect used
	rows, err := db.Query("SELECT cidr FROM workers")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	used := map[string]bool{}
	for rows.Next() {
		var s sql.NullString
		rows.Scan(&s)
		if s.Valid && s.String != "" {
			ip := strings.Split(s.String, "/")[0]
			used[ip] = true
		}
	}

	// helpers
	ipToUint := func(ip net.IP) uint32 {
		b := ip.To4()
		return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	}
	uintToIP := func(u uint32) net.IP {
		return net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
	}

	nw := ipToUint(ipnet.IP)
	ones, bits := ipnet.Mask.Size()
	hostBits := uint(bits - ones)
	broadcast := nw | ((1<<hostBits) - 1)
	for u := nw + 1; u < broadcast; u++ {
		ip := uintToIP(u)
		if ipnet.Contains(ip) {
			ipStr := ip.String()
			if !used[ipStr] {
				return ipStr + "/32", nil
			}
		}
	}
	return "", fmt.Errorf("no available addresses in %s", MASTER_NETWORK)
}

// setupWorkerMesh creates the interface on the new worker and connects it to all existing workers (full mesh)
func setupWorkerMesh(db *sql.DB, new *Worker) {
	log.Printf("MASTER: setup mesh for new worker %s (%s)", new.Name, new.IP)
	client := &http.Client{Timeout: 5 * time.Second}

	// 1) create interface on new worker
	ifaceReq := map[string]interface{}{"iface": "wg0", "private_key": new.PrivateKey, "listen_port": WG_PORT, "address": new.CIDR}
	b, _ := json.Marshal(ifaceReq)
	urlNewIface := fmt.Sprintf("http://%s:%d/api/wg/interface", new.IP, new.Port)
	log.Printf("MASTER: create interface on new %s -> %s payload=%s", new.Name, urlNewIface, string(b))
	req, _ := http.NewRequest("POST", urlNewIface, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", new.ApiKey)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("MASTER: create iface on new failed: %v", err)
	} else {
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("MASTER: create iface on new response status=%d body=%s", resp.StatusCode, string(respBody))
		resp.Body.Close()
	}

	// 2) iterate existing and connect
	rows, err := db.Query("SELECT id,name,ip,port,api_key,private_key,public_key,cidr FROM workers")
	if err != nil {
		log.Printf("MASTER: setupMesh db query failed: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var w Worker
		rows.Scan(&w.ID, &w.Name, &w.IP, &w.Port, &w.ApiKey, &w.PrivateKey, &w.PublicKey, &w.CIDR)
		// skip new
		if w.IP == new.IP && w.Port == new.Port {
			continue
		}
		// skip re-creating interface on existing worker to avoid overwriting peer config
		log.Printf("MASTER: skipping interface re-create on existing worker %s (to avoid overwriting peers)", w.Name)

		// ask existing to add new peer
		peer := map[string]string{"iface": "wg0", "public_key": new.PublicKey, "allowed_ips": new.CIDR, "endpoint": fmt.Sprintf("%s:%d", new.IP, WG_PORT)}
		bp, _ := json.Marshal(peer)
		url := fmt.Sprintf("http://%s:%d/api/wg/peer", w.IP, w.Port)
		log.Printf("MASTER: POST %s payload=%s (add new on existing)", url, string(bp))
		reqP, _ := http.NewRequest("POST", url, bytes.NewReader(bp))
		reqP.Header.Set("Content-Type", "application/json")
		reqP.Header.Set("X-API-Key", w.ApiKey)
		respP, err := client.Do(reqP)
		if err != nil {
			log.Printf("MASTER: add new on existing failed for %s: %v", w.Name, err)
		} else {
			rpb, _ := io.ReadAll(respP.Body)
			log.Printf("MASTER: add new on existing response %s status=%d body=%s", w.Name, respP.StatusCode, string(rpb))
			respP.Body.Close()
		}

		// instruct new to add existing
		peer2 := map[string]string{"iface": "wg0", "public_key": w.PublicKey, "allowed_ips": w.CIDR, "endpoint": fmt.Sprintf("%s:%d", w.IP, WG_PORT)}
		b2, _ := json.Marshal(peer2)
		url2 := fmt.Sprintf("http://%s:%d/api/wg/peer", new.IP, new.Port)
		log.Printf("MASTER: POST %s payload=%s (add existing on new)", url2, string(b2))
		req2, _ := http.NewRequest("POST", url2, bytes.NewReader(b2))
		req2.Header.Set("Content-Type", "application/json")
		req2.Header.Set("X-API-Key", new.ApiKey)
		resp2, err := client.Do(req2)
		if err != nil {
			log.Printf("MASTER: add existing on new failed for %s: %v", w.Name, err)
		} else {
			r2b, _ := io.ReadAll(resp2.Body)
			log.Printf("MASTER: add existing on new response %s status=%d body=%s", w.Name, resp2.StatusCode, string(r2b))
			resp2.Body.Close()
		}
	}
	// short delay to allow propagation
	time.Sleep(500 * time.Millisecond)
}
