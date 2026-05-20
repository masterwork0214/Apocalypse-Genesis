# Apocalypse-Genesis

HSQSL private server emulator — a reverse-engineered mock backend for offline/local play.

## Components

| Module | Description |
|--------|-------------|
| `start_mock_backend.py` | Launcher — starts all mock servers |
| `mock_server/mock_gate.py` | TCP Gate server — handshake and client routing |
| `mock_server/mock_game.py` | TCP Game server — entity lifecycle and RPC dispatch |
| `mock_server/mock_http.py` | HTTP server — intercepts NetEase SDK requests |
| `mock_server/proto_utils.py` | Shared utilities — protobuf, ARC4 cipher, BSON, RSA |
| `manage_hosts.py` | Windows hosts file manager — redirects SDK domains to localhost |
| `marshal_dump_py3.py` | Python 3 serializer for NeoX marshal binary format |

## Quick Start

```bash
# 1. Install dependencies
pip install cryptography

# 2. Redirect SDK domains (run as Administrator)
python manage_hosts.py add

# 3. Start all mock servers
python start_mock_backend.py

# 4. Launch the game client
```

## Protocol

Based on reverse-engineered MobileRPC frames over TCP:
- Gate connection: seed → session key → connect → client routing
- Game connection: second handshake → account creation → RPC dispatch
- HTTP interception: SDK gateway, update CDN, logging endpoints
