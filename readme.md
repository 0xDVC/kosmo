# kosmo

yet another deployment tool. my vision is a self-hosted tool with no vendor lockin. absolute ownership of your infra. i love some existent solutions.

but this is a rabbit-hole project. a frying pan to fire situation. currently, building for only go apps.

## current approach

http-based deployment. no ssh, no git. client sends tarball over http, server builds and runs.

-- uses ed25519 signatures. server gives you a token, you sign requests with it.

-- client tarballs code, streams to server, server builds with `go build`, runs process.

-- achieve zero-downtime with blue-green deployment and health checks.

-- one server handles all apps for now, each gets its own port.

## quick start

### 1. server Setup
```bash
# get binary build from code 
GOOS=<os> GOARCH=<arch> go build

# export binary to server and generate server keypair and get KOSMO-token
./kosmo setup

# start the server
./kosmo start --port 8080
```

### 2. deploy apps
```bash
# generate binary for client(i use darwin)
GOOS=<os> GOARCH=<arch> go build

# login once
./kosmo login --server http://<server-ip/url>:8080 --key KOSMO-XXXX

# in your app directory
./kosmo init
./kosmo deploy
```
## commands
- `kosmo setup` - generate server keypair
- `kosmo start` - start server
- `kosmo login` - authenticate with server
- `kosmo init` - initialize project
- `kosmo deploy` - deploy app
```

