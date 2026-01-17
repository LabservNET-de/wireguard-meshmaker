wgmesh Master

Kurz: Master speichert Worker in einer SQLite DB (`/etc/wireguard/master-sw/master.db`) und ruft per HTTP die Worker APIs an, um Peers für Full‑Mesh zu konfigurieren.

Starten (lokal):
- `go run main.go` (läuft auf :8080)

Beispiel Worker hinzufügen:
POST http://master:8080/api/workers
{
  "name":"worker-a",
  "ip":"192.0.2.10",
  "port":8080,
  "api_key":"secret-for-worker",
  "cidr":"10.100.0.0/32"
}

Hinweis: Master versucht `wg genkey`/`wg pubkey` auszuführen, um Keys zu erzeugen. Stelle sicher, dass `wg` installiert ist.
