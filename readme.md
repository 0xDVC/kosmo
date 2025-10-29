# kosmo

yet another deployment tool. my vision is a self-hosted tool with no vendor lockin. absolute ownership of your infra. i love some existent solutions.

but this is a rabbit-hole project. a frying pan to fire situation. currently, building for only go apps. in a make it work stage first.

WIP:: testing on my homelab server at the moment....
there's always a less complicated way to doing something. tradeoffs matter.

## current approach

http-based deployment. no ssh, no git. client sends tarball over http, server builds and runs.

-- uses ed25519 signatures. server gives you a token, you sign the full request payload with it.

-- client allowlist. only pre-approved clients can deploy. simple pubkey list, no complex permissions yet.

-- blue-green deployment. start new version first, health check it, then switch traffic. if it fails, keep the old version running.

-- per-app logs. each app gets its own log file. no more mixing output in kosmo's logs.

-- rollback support. `kosmo rollback --app <name>` to go back to previous version. keeps last 2 builds per app.

-- health checks. 30s timeout on `/health` endpoint. no weak port-checking fallbacks.

-- daemon mode. runs in background, proper pid file management, graceful shutdown.

-- one server handles all apps for now, each gets its own port.

## commands

```bash
# server setup
kosmo setup                    # generate server keys
kosmo start                    # start daemon
kosmo add-client --pubkey <key> # add client to allowlist

# client setup  
kosmo login --server <url> --key <token>  # configure client
kosmo deploy --server <url>               # deploy current dir

# management
kosmo logs --app <name>        # tail app logs
kosmo rollback --app <name>    # rollback to previous version
kosmo status                   # check if running
kosmo stop                     # stop daemon
```