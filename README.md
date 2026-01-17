# WireGuard MeshMaker

WireGuard MeshMaker is a simple tool to create a **WireGuard-based mesh network** between multiple servers. With this tool, you can connect all your servers to each other automatically using a web interface.

## Features

* Automatically configures a WireGuard mesh network.
* Simple **WebUI** to manage your servers.
* Easy setup with minimal dependencies.
* Written in **Go** for fast and lightweight execution.

## Requirements

* [WireGuard](https://www.wireguard.com/install/)
* [Go](https://golang.org/doc/install) (for building the project)

## Installation

1. Clone the repository:

```
git clone https://github.com/yourusername/wireguard-meshmaker.git
cd wireguard-meshmaker
```

2. Build the project (optional if using precompiled binaries):

```
go build ./...
```

## Usage

### Start the Master

The master server is where you register all your nodes and manage the mesh network.

```
./master
```

Open the WebUI in your browser to add servers. The master handles all configuration automatically.

### Start a Worker

Each server you want to add to the mesh runs the worker with its API key:

```
WORKER_API_KEY=your_api_key ./worker
```

* `WORKER_API_KEY` is generated in the Master WebUI for each worker.
* The worker connects to the master and joins the mesh network.

## How It Works

1. Start the **Master** server.
2. Register all your servers in the **WebUI**.
3. Start **Workers** on each server with their API keys.
4. All servers are automatically connected in a fully meshed WireGuard network.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## License

MIT Lic
