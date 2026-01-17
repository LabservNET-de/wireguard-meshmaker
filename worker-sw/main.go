package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const CONF_DIR = "/etc/wireguard"

func main() {
	apiKey := os.Getenv("WORKER_API_KEY")
	if apiKey == "" {
		log.Fatalf("WORKER_API_KEY not set")
	}
	log.Printf("WORKER: CONF_DIR=%s WORKER_API_KEY_PRESENT=%t", CONF_DIR, apiKey != "")

	if err := os.MkdirAll(CONF_DIR, 0700); err != nil {
		log.Fatalf("mkdir conf dir: %v", err)
	}

	http.HandleFunc("/api/wg/interface", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("WORKER: incoming %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		b, _ := io.ReadAll(r.Body)
		log.Printf("WORKER: /api/wg/interface body=%s", string(b))
		if !checkAuth(r, apiKey) {
			log.Printf("WORKER: auth failed for interface create (X-API-Key present=%t)", r.Header.Get("X-API-Key") != "")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			Iface      string `json:"iface"`
			PrivateKey string `json:"private_key"`
			ListenPort int    `json:"listen_port"`
			Address    string `json:"address"` // e.g. 10.100.0.2/22
		}
		if err := json.Unmarshal(b, &req); err != nil {
			log.Printf("WORKER: invalid json: %v", err)
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if req.Iface == "" || req.PrivateKey == "" || req.Address == "" {
			log.Printf("WORKER: missing fields in interface create: iface=%s address=%s listen=%d", req.Iface, req.Address, req.ListenPort)
			http.Error(w, "missing fields", http.StatusBadRequest)
			return
		}
		conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nListenPort = %d\n",
			req.PrivateKey, req.Address, req.ListenPort)
		path := filepath.Join(CONF_DIR, req.Iface+".conf")
		// preserve existing [Peer] blocks if present to avoid overwriting peers
		existingData, _ := os.ReadFile(path)
		peers := ""
		if len(existingData) > 0 {
			s := string(existingData)
			if idx := strings.Index(s, "\n[Peer]"); idx != -1 {
				peers = s[idx:]
			}
		}
		newConf := conf + peers
		if err := os.WriteFile(path, []byte(newConf), 0600); err != nil {
			log.Printf("WORKER: write conf failed: %v", err)
			http.Error(w, "write conf failed", http.StatusInternalServerError)
			return
		}
		log.Printf("WORKER: wrote interface conf to %s (len=%d) preserved-peers=%t", path, len(newConf), peers!="")
		// enable & start via systemd: wg-quick@<iface>.service
		ensOut, ensErr := exec.Command("systemctl", "enable", "wg-quick@"+req.Iface).CombinedOutput()
		log.Printf("WORKER: systemctl enable wg-quick@%s output=%s err=%v", req.Iface, string(ensOut), ensErr)
		startOut, startErr := exec.Command("systemctl", "start", "wg-quick@"+req.Iface).CombinedOutput()
		if startErr != nil {
			log.Printf("WORKER: systemctl start wg-quick@%s failed: %v output=%s", req.Iface, startErr, string(startOut))
			// fallback to wg-quick up if systemctl start fails
			fbOut, fbErr := exec.Command("wg-quick", "up", req.Iface).CombinedOutput()
			if fbErr != nil {
				log.Printf("WORKER: fallback wg-quick up also failed: %v output=%s", fbErr, string(fbOut))
			} else {
				log.Printf("WORKER: fallback wg-quick up output: %s", string(fbOut))
			}
		} else {
			log.Printf("WORKER: systemctl start wg-quick@%s output=%s", req.Iface, string(startOut))
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("interface created\n"))
	})

	http.HandleFunc("/api/wg/peer", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("WORKER: incoming %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		b, _ := io.ReadAll(r.Body)
		log.Printf("WORKER: /api/wg/peer body=%s", string(b))
		if !checkAuth(r, apiKey) {
			log.Printf("WORKER: auth failed for peer add (X-API-Key present=%t)", r.Header.Get("X-API-Key") != "")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			Iface     string `json:"iface"`
			PublicKey string `json:"public_key"`
			AllowedIPs string `json:"allowed_ips"`
			Endpoint  string `json:"endpoint"`
		}
		if err := json.Unmarshal(b, &req); err != nil {
			log.Printf("WORKER: invalid json for peer add: %v", err)
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if req.Iface == "" || req.PublicKey == "" || req.AllowedIPs == "" {
			log.Printf("WORKER: missing fields in peer add: iface=%s pub=%s allowed=%s", req.Iface, req.PublicKey, req.AllowedIPs)
			http.Error(w, "missing fields", http.StatusBadRequest)
			return
		}
		// add peer via wg set
		args := []string{"set", req.Iface, "peer", req.PublicKey, "allowed-ips", req.AllowedIPs}
		if req.Endpoint != "" {
			args = append(args, "endpoint", req.Endpoint)
		}
		log.Printf("WORKER: executing wg %v", args)
		if out, err := exec.Command("wg", args...).CombinedOutput(); err != nil {
			log.Printf("WORKER: wg set failed: %v output=%s", err, string(out))
			http.Error(w, "wg set failed", http.StatusInternalServerError)
			return
		} else {
			log.Printf("WORKER: wg set success output=%s", string(out))
		}
		// append to config file for persistence
		path := filepath.Join(CONF_DIR, req.Iface+".conf")
		peerconf := fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", req.PublicKey, req.AllowedIPs)
		if req.Endpoint != "" {
			peerconf = fmt.Sprintf("%sEndpoint = %s\n", peerconf, req.Endpoint)
		}
		// ensure we don't append duplicate peer blocks
		existingData, _ := os.ReadFile(path)
		if strings.Contains(string(existingData), "PublicKey = "+req.PublicKey) {
			log.Printf("WORKER: peer %s already present in %s, skipping append", req.PublicKey, path)
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("peer added (already present)\n"))
			return
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			log.Printf("WORKER: open conf append failed: %v", err)
			// still return success because peer was set
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("peer added (but conf append failed)\n"))
			return
		}
		defer f.Close()
		if n, err := f.WriteString(peerconf); err != nil {
			log.Printf("WORKER: append conf failed: %v", err)
		} else {
			log.Printf("WORKER: appended peer to %s bytes=%d", path, n)
		}
		// restart wg-quick service for iface to pick up persisted config
		restartOut, restartErr := exec.Command("systemctl", "restart", "wg-quick@"+req.Iface).CombinedOutput()
		log.Printf("WORKER: systemctl restart wg-quick@%s output=%s err=%v", req.Iface, string(restartOut), restartErr)
		if restartErr != nil {
			log.Printf("WORKER: systemctl restart failed, attempting wg-quick down/up as fallback")
			downOut, downErr := exec.Command("wg-quick", "down", req.Iface).CombinedOutput()
			log.Printf("WORKER: wg-quick down output=%s err=%v", string(downOut), downErr)
			upOut, upErr := exec.Command("wg-quick", "up", req.Iface).CombinedOutput()
			log.Printf("WORKER: wg-quick up output=%s err=%v", string(upOut), upErr)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("peer added\n"))
	})

	http.HandleFunc("/api/wg/status", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("WORKER: incoming %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		out, err := exec.Command("wg", "show").CombinedOutput()
		if err != nil {
			log.Printf("WORKER: wg show failed: %v output=%s", err, string(out))
			http.Error(w, string(out), http.StatusInternalServerError)
			return
		}
		log.Printf("WORKER: wg show output len=%d", len(out))
		w.Write(out)
	})

	addr := ":8080"
	log.Printf("worker listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func checkAuth(r *http.Request, expected string) bool {
	k := r.Header.Get("X-API-Key")
	return k != "" && strings.EqualFold(k, expected)
}
