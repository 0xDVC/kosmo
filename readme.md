# kosmo

yet another deployment tool. my vision is a self-hosted tool with no vendor lockin. absolute ownership of your infra. i love some existent solutions.

but this is a rabbit-hole project. a frying pan to fire situation. currently, building for only go apps. in a make it work stage first.

WIP:: testing on my homelab server at the moment....
there's always a less complicated way to doing something. tradeoffs matter.
## current approach

http-based deployment. no ssh, no git. client sends tarball over http, server builds and runs.

-- uses ed25519 signatures. server gives you a token, you sign requests with it.

-- client tarballs code, streams to server, server builds with `go build`, runs process.

-- achieve zero-downtime with blue-green deployment and health checks.

-- one server handles all apps for now, each gets its own port.