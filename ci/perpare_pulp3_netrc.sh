#!/usr/bin/env sh
set -evx
echo "machine ${PULP3_SERVER_URL}\nlogin ${PULP3_SERVER_LOGIN}\npassword ${PULP3_SERVER_PASSWORD}\n" > ~/.netrc
