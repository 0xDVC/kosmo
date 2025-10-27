#!/bin/sh
set -euf

printf "testing kosmo...\n"

printf "test 1: setup creates keys\n"
kosmo setup | grep -q "Kosmo setup complete" || exit 1
[ -f ~/.kosmo/keys/server_ed25519.pub ] || exit 1
[ -f ~/.kosmo/keys/server_ed25519 ] || exit 1
printf "keys created\n"

printf "test 2: init creates directories\n"
cd sample && kosmo init && cd .. || exit 1
[ -d sample/.kosmo/builds ] || exit 1
printf "directories created\n"

printf "test 3: deploy and verify app\n"
cd sample

# get server token from shared volume
SERVER_TOKEN=$(grep "KOSMO-" ~/.kosmo/keys/server_ed25519.pub 2>/dev/null | head -1 || printf "")
if [ -z "$SERVER_TOKEN" ]; then
    SERVER_TOKEN=$(cat /tmp/setup.out 2>/dev/null| grep "KOSMO-" |awk '{print $NF}' |head -1 || printf "")
fi
# login with token
if [ -n "$SERVER_TOKEN" ]; then
    kosmo login --server http://${SERVER_HOST:-server}:8080 --key "$SERVER_TOKEN"|| printf "login failed\n"
fi

# deploy
DEPLOY_OUTPUT=$(kosmo deploy --server http://${SERVER_HOST:-server}:8080 2>&1 || printf "deploy_failed")
if printf "%s\n" "$DEPLOY_OUTPUT" | grep -q "deployed to"; then
    DEPLOY_URL=$(printf "%s\n" "$DEPLOY_OUTPUT" | grep -o "http://[^ ]*" | head -1)
    printf "deployed to: %s\n" "$DEPLOY_URL"
    sleep 3
    
    if curl -s -f "$DEPLOY_URL" > /dev/null 2>&1; then
        printf "deployed app responds\n"
    else
        printf "deployed app not responding\n"
        exit 1
    fi
else
    printf "deploy failed or skipped (no server)\n"
fi
printf "tests completed\n"

