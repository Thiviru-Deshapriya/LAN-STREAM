# ⚡ LAN Stream — Zero-Latency PHP Video Streamer

A single-file PHP video streamer designed for local network use.  
No transcoding. No third-party libraries. No latency.

---

## Features

| Feature | Detail |
|---|---|
| **Zero latency** | Direct byte-range file transfer — no re-encoding |
| **Seekable** | HTTP `Content-Range` / `Accept-Ranges` headers |
| **Dropless** | `Connection: keep-alive` + chunked 512KB reads |
| **Multi-device** | Any browser on your LAN can stream |
| **Auto-advance** | Plays next file when current ends |
| **Copy stream URL** | Share the URL with any device on the LAN |

---

## Quick Start

### Requirements
- PHP 7.4+ (check: `php -v`)
- Any modern browser on the LAN

### Linux / macOS
```bash
chmod +x start.sh
./start.sh
# Or with a custom port:
./start.sh 9000
```

### Windows
Double-click `start.bat`  
*(Make sure `php` is in your PATH)*

### Manual start
```bash
php -S 0.0.0.0:8888 -t /path/to/lan-stream/
```

---

## Usage

1. Drop video files into the `videos/` folder  
   Supported: `.mp4` `.mkv` `.webm` `.avi` `.mov` `.m4v` `.ts` `.flv`

2. Open the displayed LAN URL on any device  
   e.g. `http://192.168.1.10:8888/stream.php`

3. Click a file to stream — seeking works instantly

---

## Keyboard Shortcuts

| Key | Action |
|---|---|
| `Space` | Play / Pause |
| `←` | Previous file |
| `→` | Next file |

---

## Endpoints (REST)

| URL | Description |
|---|---|
| `?action=ui` | Player interface (default) |
| `?action=list` | JSON list of all videos |
| `?action=stream&file=NAME` | Stream a specific file |
| `?action=info&file=NAME` | JSON metadata for a file |

---

## How Zero-Latency Works

1. **No transcoding** — PHP reads the raw file bytes and sends them directly
2. **Byte-range streaming** — browser requests only the bytes it needs (enables instant seek)
3. **`Accept-Ranges: bytes`** — tells browser seeking is supported
4. **`Connection: keep-alive`** — TCP connection stays open between requests (dropless)
5. **Output buffering disabled** — bytes leave the server immediately without being held
6. **`ignore_user_abort(false)`** — stops reading file the instant client disconnects (no CPU waste)

---

## Firewall (if other devices can't connect)

**Windows:**  
Allow PHP through Windows Firewall, or run:
```
netsh advfirewall firewall add rule name="LAN Stream" dir=in action=allow protocol=TCP localport=8888
```

**macOS:**  
System Settings → Privacy & Security → Firewall → Allow PHP

**Linux:**  
```bash
sudo ufw allow 8888/tcp
```

---

## File Structure

```
lan-stream/
├── stream.php      ← Main app (UI + streaming logic)
├── start.sh        ← Linux/macOS launcher
├── start.bat       ← Windows launcher
├── README.md
├── videos/         ← Drop your video files here
└── logs/
    └── stream.log  ← Connection log
```
