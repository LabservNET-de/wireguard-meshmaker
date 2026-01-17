wgmesh Worker

Kurz: Worker öffnet eine HTTP API (:8080) und erwartet `X-API-Key` im Header (gleich `WORKER_API_KEY` env).

Endpoints:
- POST /api/wg/interface  (body: iface, private_key, listen_port, address)
- POST /api/wg/peer       (body: iface, public_key, allowed_ips, endpoint)
- GET  /api/wg/status

Konfigurationen und generierte WireGuard‑Files werden unter `/etc/wireguard/<iface>.conf` abgelegt (0600).

Hinweis: Nach dem Erstellen eines Interfaces führt der Worker `systemctl enable wg-quick@<iface>` und `systemctl start wg-quick@<iface>` aus. Wenn neue Peers hinzugefügt werden, versucht der Worker `systemctl restart wg-quick@<iface>` (bei Bedarf fällt er auf `wg-quick down` / `wg-quick up` zurück). Diese Aktionen benötigen Root / `CAP_NET_ADMIN`.

