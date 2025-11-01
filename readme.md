# kosmo

self-hosted deployment tool. no docker, no vendor lock, just `kosmo deploy`.

**status:** v0.1.0 - go-only, single host, needs testing  
**next:** v0.2 refactor for better UX (see [ARCHITECTURE.md](ARCHITECTURE.md))  
**goal:** kamal-style deploys without docker (see [ROADMAP.md](ROADMAP.md))

## what it does

- http-based deploys (no ssh, no git, no docker)
- ed25519 signatures + client allowlist auth
- blue-green deployments (zero-downtime)
- rollback support (keeps last 2 versions)
- daemon mode (background process, survives restarts)
- per-app logs + state persistence

## quickstart (v0.1 - current)

### 1. server setup (one-time, on your VPS)

```bash
# build from source
git clone https://github.com/0xDVC/kosmo
cd kosmo
go build -o kosmo

# generate server keys
./kosmo server setup
# → prints: KOSMO-xxxxxxxxxx (save this)

# start daemon
./kosmo server up
```

server runs on port 8080. logs: `~/.kosmo/kosmo.log`

---

### 2. client setup (one-time, on your laptop)

```bash
# build kosmo
git clone https://github.com/0xDVC/kosmo
cd kosmo
go build -o kosmo

# configure client (use server key from step 1)
./kosmo auth login --server http://your-server:8080 --key KOSMO-xxxxxxxxxx

# → prints your client public key: KOSMO-yyyyyyyyyy
# → copy this key
```

---

### 3. add client to server allowlist

```bash
# on the server
./kosmo clients add KOSMO-yyyyyyyyyy

# verify
./kosmo clients list
```

---

### 4. deploy your go app

```bash
# on your laptop, in your go project
cd /path/to/your-app

# your app must have
# - go.mod
# - /health endpoint (returns 200)
# - reads PORT env var

# deploy
/path/to/kosmo deploy --server http://your-server:8080

# → builds on server
# → health checks /health
# → swaps to new version
```

---

### 5. manage apps

```bash
# list all running apps
./kosmo apps list

# tail logs
./kosmo apps logs myapp

# restart
./kosmo apps restart myapp

# rollback to previous version
./kosmo apps rollback myapp

# stop server
./kosmo server down
```

## commands reference (v0.1)

```bash
# server (run on VPS)
kosmo server setup                    # generate keys, prints KOSMO-xxx
kosmo server up                       # start daemon
kosmo server up -p 8081               # custom port
kosmo server down                     # stop daemon
kosmo server status                   # check status

# client management (on server)
kosmo clients add <pubkey>            # add client to allowlist
kosmo clients remove <pubkey>         # revoke access
kosmo clients list                    # show all allowed clients

# authentication (run on laptop, one-time per machine)
kosmo auth login --server <url> --key <KOSMO-xxx>  # configure client

# deployment (run in project)
kosmo deploy --server <url>           # deploy current directory

# app management (run anywhere)
kosmo apps list                       # show all running apps
kosmo apps logs <name>                # tail logs
kosmo apps restart <name>             # restart
kosmo apps rollback <name>            # rollback to previous version

# utilities
kosmo completion                      # install shell completion
kosmo --help                          # show help
```

## requirements

### server
- linux or macos (no windows support)
- go 1.21+ installed (for building apps)
- port 8080 open (or custom port)

### client
- any os with go installed
- network access to server

## app requirements

your go app must:
1. have a `go.mod` file
2. expose a `/health` endpoint that returns 200
3. read `PORT` env var for which port to listen on

example minimal app:

```go
package main

import (
    "fmt"
    "net/http"
    "os"
)

func main() {
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }

    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(200)
        fmt.Fprint(w, "ok")
    })

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprint(w, "hello from kosmo")
    })

    fmt.Printf("listening on :%s\n", port)
    http.ListenAndServe(":"+port, nil)
}
```

## file structure

### global config (`~/.kosmo/` - never committed)

```
~/.kosmo/
├── auth.json            # your client keys + approved servers
├── server_config.json   # server: allowlist + settings
├── keys/
│   ├── server_ed25519   # server private key
│   └── server_ed25519.pub # server public key
├── kosmo.pid            # server pid file
├── kosmo.log            # server logs
├── state.json           # running apps state
└── apps/
    └── myapp/
        ├── 1730393845/  # version timestamp
        │   ├── app      # built binary
        │   └── app.log  # app stdout/stderr
        └── current -> 1730393845/
```

### per-app config (`.kosmo/` in project - committed to git)

```
/path/to/myapp/
├── .kosmo/
│   └── config.toml      # app name, server, health check, env vars
├── go.mod               # or package.json, requirements.txt, etc.
└── main.go
```

**`.kosmo/config.toml` example:**
```toml
[app]
name = "myapp"
server = "http://your-server:8080"

[health]
path = "/health"
timeout = 30

[env]
# future: environment variables
DATABASE_URL = "postgres://..."

[limits]
# future: resource limits
memory = "512M"
cpu = 0.5
```

## what's next? (v0.2 refactor)

**v0.1 issues:**
- must copy/paste pubkeys manually (annoying)
- must specify `--server` every deploy (repetitive)
- no per-app config file (can't customize health checks, env vars)
- client keys in `~/.kosmo/config.json` mixed with server url (confusing)

**v0.2 improvements (planned):**
- `kosmo auth login <url>` → auto-enrollment or approval flow
- `kosmo init` in project → creates `.kosmo/config.toml`
- `kosmo deploy` → reads config, no flags needed
- client keys in `~/.kosmo/auth.json` (like `~/.ssh/`)
- app config in `.kosmo/config.toml` (checked into git)

see [ARCHITECTURE.md](ARCHITECTURE.md) for v0.2 design.

## roadmap

**v0.1** (current - testing phase):
- [x] go app deploys
- [x] ed25519 auth + allowlist
- [x] blue-green + rollback
- [x] daemon mode + state persistence
- [ ] test end-to-end
- [ ] fix bugs

**v0.2** (next - better ux):
- [ ] `kosmo init` command
- [ ] auto-enrollment
- [ ] `.kosmo/config.toml` per app
- [ ] environment variables

**v0.3** (future):
- [ ] nixpacks (multi-language)
- [ ] caddy integration (tls + domains)
- [ ] cgroups (resource limits)

see [ROADMAP.md](ROADMAP.md) for full timeline.

## security

see [SECURITY.md](SECURITY.md) for honest security assessment. tl;dr: it's http-only, use a reverse proxy with tls in production.

## contributing

this is a 0.x learning project. feel free to open issues or prs, but expect breaking changes.

## license

mit