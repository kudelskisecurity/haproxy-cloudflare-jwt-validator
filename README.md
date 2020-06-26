# Name

haproxy-cloudflare-jwt-validator - JSON Web Token validation for haproxy

# Description

This was tested & developed with HAProxy version 1.8.25 & Lua version 5.3.
This library provides the ability to validate JWT headers sent by Cloudflare Access. 

# Installation

Install the following dependencies:

* [haproxy-lua-http](https://github.com/haproxytech/haproxy-lua-http)
* [rxi/json](https://github.com/rxi/json.lua)
* [wahern/luaossl](https://github.com/wahern/luaossl)

Extract base64.lua & jwtverify.lua to the same directory like so:

```shell
git clone git@github.com:kudelskisecurity/haproxy-cloudflare-jwt-validator.git
sudo cp haproxy-cloudflare-jwt-validator/src/* /usr/local/share/lua/5.3
```

# Version

0.1.0

# Usage

JWT Issuer: `https://test.cloudflareaccess.com` (replace with yours in the config below)

Add the following settings in your `/etc/haproxy/haproxy.cfg` file: 

Define a HAProxy backend, DNS Resolver, and ENV variables with the following names:

```
global
  lua-load  /usr/local/share/lua/5.3/jwtverify.lua
    setenv  OAUTH_HOST     test.cloudflareaccess.com
    setenv  OAUTH_JWKS_URL https://|cloudflare_jwt|/cdn-cgi/access/certs
    setenv  OAUTH_ISSUER   https://"${OAUTH_HOST}"

backend cloudflare_jwt
  mode http
  default-server inter 10s rise 2 fall 2
  server "${OAUTH_HOST}" "${OAUTH_HOST}":443 check resolvers dnsresolver resolve-prefer ipv4

resolvers dnsresolver
  nameserver dns1 1.1.1.1:53
  nameserver dns2 1.0.0.1:53
  resolve_retries 3
  timeout retry 1s
  hold nx 10s
  hold valid 10s
```

Obtain your Application Audience (AUD) Tag from Cloudflare and define your backend with JWT validation:

```
backend my_jwt_validated_app
  mode http
  http-request deny unless { req.hdr(Cf-Access-Jwt-Assertion) -m found }
  http-request set-var(txn.audience) str("4714c1358e65fe4b408ad6d432a5f878f08194bdb4752441fd56faefa9b2b6f2")
  http-request lua.jwtverify
  http-request deny unless { var(txn.authorized) -m bool }
  server haproxy 127.0.0.1:8080
```
