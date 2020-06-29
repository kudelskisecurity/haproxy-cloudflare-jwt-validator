#!/usr/bin/env bash

mkdir -p cloudflare_mock/cdn-cgi/access

printf "\nGenerating Private Key & Certificate: \n"
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" \
    -keyout certs/private.key  -out certs/certificate.pem

CERT=$(cat certs/certificate.pem)

printf "\nAdding Certificate to JWKS Endpoint: \n"
jq -n --arg cert "$CERT" '{public_certs: [{kid: "1", cert: $cert}, {kid: "2", cert: $cert}]}' \
  > cloudflare_mock/cdn-cgi/access/certs && echo "done"

docker-compose stop
docker-compose up -d

CLAIM='{
  "aud": [
    "1234567890abcde1234567890abcde1234567890abcde"
  ],
  "email": "random-email@email.com",
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true,
  "iss": "http://cloudflare_mock",
  "iat": 1593204858,
  "nbf": 1593204858,
  "exp": 3993204858,
  "type": "app",
  "identity_nonce": "11111111111",
  "custom": {}
}'

while ! nc -z localhost 8080; do
  sleep 0.1
done

#wait a couple of seconds for the backends to start for haproxy
sleep 3

printf "\nCURL Response with Bad Cf-Access-Jwt-Assertion header: \n"
curl -H "Cf-Access-Jwt-Assertion: non-valid-token" localhost:8080

JWT_TOKEN=$(jwtgen -a RS256 -p certs/private.key --claims "$CLAIM")

printf "\nCURL Response with Valid Cf-Access-Jwt-Assertion header: \n"
curl -H "Cf-Access-Jwt-Assertion: ${JWT_TOKEN}" localhost:8080

docker-compose stop