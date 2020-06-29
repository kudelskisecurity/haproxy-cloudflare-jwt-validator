--
-- JWT Validation implementation for HAProxy Lua host
-- This script is a heavily modified version of the following: https://github.com/haproxytech/haproxy-lua-jwt
-- 2020-05-21 - Bojan Zelic - Enabled support for JWKS urls, custom headers, multiple audience tokens
-- Copyright (c) 2019. Adis Nezirovic <anezirovic@haproxy.com>
-- Copyright (c) 2019. Baptiste Assmann <bassmann@haproxy.com>
-- Copyright (c) 2019. Nick Ramirez <nramirez@haproxy.com>
-- Copyright (c) 2019. HAProxy Technologies LLC
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, version 2 of the License
--
-- Use HAProxy 'lua-load' to load optional configuration file which
-- should contain config table.
-- Default/fallback config
if not config then
    config = {
        publicKeys = {
            keys = {},
            expiresIn = 1000 -- 1 second
        },
        max_cache = 24 * 60 * 60, -- 24 hours
        issuer = nil,
        jwks_url = nil
    }
end

local json   = require 'json'
local base64 = require 'base64'
local http   = require 'http'

local openssl = {
    pkey = require 'openssl.pkey',
    digest = require 'openssl.digest',
    x509 = require 'openssl.x509'
}

local function log_alert(msg)
    core.Alert("jwtverify.lua: <alert> - "..tostring(msg))
end

local function log_info(msg)
    core.Info("jwtverify.lua: <info> - "..tostring(msg))
end

local function log_debug(msg)
    core.Debug("jwtverify.lua: <debug> - "..tostring(msg))
end

local function log_notice(msg)
    core.log(core.notice, "jwtverify.lua: <notice> - "..tostring(msg))
end

local function dump(o)
    if type(o) == 'table' then
        local s = '{ '
        for k,v in pairs(o) do
            if type(k) ~= 'number' then k = '"'..k..'"' end
            s = s .. '['..k..'] = ' .. dump(v) .. ','
        end
        return s .. '} '
    else
        return tostring(o)
    end
end

local function decodeJwt(authorizationHeader)
    local headerFields = core.tokenize(authorizationHeader, " .")

    if #headerFields ~= 3 then
        log_info("Improperly formated Authorization header. Should be followed by 3 token sections.")
        return nil
    end

    local token = {}
    token.header = headerFields[1]
    token.headerdecoded = json.decode(base64.decode(token.header))

    token.payload = headerFields[2]
    token.payloaddecoded = json.decode(base64.decode(token.payload))

    token.signature = headerFields[3]
    token.signaturedecoded = base64.decode(token.signature)

    log_info('Authorization header: ' .. authorizationHeader)
    log_info('Decoded JWT header: ' .. dump(token.headerdecoded))
    log_info('Decoded JWT payload: ' .. dump(token.payloaddecoded))

    return token
end

local function algorithmIsValid(token)
    if token.headerdecoded.alg == nil then
        log_info("No 'alg' provided in JWT header.")
        return false
    elseif token.headerdecoded.alg ~= 'RS256' then
        log_info("RS256 supported. Incorrect alg in JWT: " .. token.headerdecoded.alg)
        return false
    end

    return true
end

local function signatureIsValid(token, publicKey)
    local digest = openssl.digest.new('SHA256')
    digest:update(token.header .. '.' .. token.payload)

    local isVerified = publicKey:verify(token.signaturedecoded, digest)
    return isVerified
end

local function has_value (tab, val)
    if tab == val then
        return true
    end

    for _, value in ipairs(tab) do
        if value == val then
            return true
        end
    end

    return false
end

local function expirationIsValid(token)
    return os.difftime(token.payloaddecoded.exp, core.now().sec) > 0
end

local function issuerIsValid(token, expectedIssuer)
    return token.payloaddecoded.iss == expectedIssuer
end

local function audienceIsValid(token, expectedAudience)
    -- audience is sometimes stored as an array of strings
    -- sometimes it's stored as a string
    return has_value(token.payloaddecoded.aud, expectedAudience)
end

-- This function loads the JSON from our JWKS url. However because we cannot do DNS lookups in haproxy, We have to
-- use the IP address directly. We depend on a backend that's set in order for Haproxy to resolve an IP address
-- for the JWKS url.
-- If there are any errors (ex: if cloudflare endpoint is down... then we will rely on the last-used public key
local function getJwksData(url)
    --check for existence of public keys

    local publicKeys = {}
    local expiresIn = 60 * 60 -- 1 hour default

    local be = string.gsub(string.match(url, '|.*|'), '|', '')
    local addr
    local server_name
    for name, server in pairs(core.backends[be].servers) do
        local status = server:get_stats()['status']
        if status == "no check" or status:find("UP") == 1 then
            addr = server:get_addr()
            server_name = name
            break
        end
    end

    if addr == nil or addr == '<unknown>' then
        log_info("No servers available for auth-request backend: '" .. be .. "'")
        return {
            keys = config.publicKeys.keys,
            expiresIn = 1 -- 1 second
        }
    end

    local ip_url = string.gsub(url, '|'..be..'|', addr)

    log_info('retrieving JWKS Public Key Data')

    local response, err = http.get{url=ip_url, headers={Host=server_name}}
    if not response then
        log_alert(err)
        return {
            keys = config.publicKeys.keys,
            expiresIn = 1 -- 1 second
        }
    end

    if response.status_code ~= 200 then
        log_info("JWKS data is not available.")
        log_info("status_code: " .. response.status_code or "<none>")
        log_info("body: " .. dump(response.content) or "<none>")
        log_info("headers: " .. dump(response.headers) or "<none>")
        log_info("reason: " .. response.reason or "<none>")

        -- return already set publicKeys if already set
        if is_cached then
            return {
                keys = config.publicKeys.keys,
                expiresIn = 60 -- 60 second
            }
        end

        log_alert("JWKS data is not available")
    end

    local JWKS_response = json.decode(response.content)

    for _,v in pairs(JWKS_response.public_certs) do
        table.insert(publicKeys,openssl.x509.new(v.cert):getPublicKey())
        log_notice("Public Key Cached: " .. v.kid)
    end

    local max_age

    if response.headers['cache-control'] then
        local has_max_age = string.match(response.headers['cache-control'], "max%-age=%d+")
        if has_max_age then
            max_age = tonumber(string.gsub(has_max_age, 'max%-age=', ''), 10)
        end
    end

    if max_age then
        expiresIn = math.min(max_age, config.max_cache)
    else
        log_info('cache-control headers not able to be retrieved from JWKS endpoint')
    end

    return {
        keys = publicKeys,
        expiresIn = expiresIn
    }

end

function jwtverify(txn)

    local issuer = config.issuer
    local audience = txn.get_var(txn, 'txn.audience')
    local signature_valid = false

    -- 1. Decode and parse the JWT
    local token = decodeJwt(txn.sf:req_hdr("cf-access-jwt-assertion"))
    if token == nil then
        log_info("Token could not be decoded.")
        goto out
    end

    -- 2. Verify the signature algorithm is supported (RS256)
    if algorithmIsValid(token) == false then
        log_info("Algorithm not valid.")
        goto out
    end

    -- 3. Verify the signature with the certificate
    for k,pem in pairs(config.publicKeys.keys) do
        signature_valid = signature_valid or signatureIsValid(token, pem)
    end

    if signature_valid == false then
        log_info("Signature not valid.")

        if not signature_valid then
            goto out
        end
    end

    -- 4. Verify that the token is not expired
    if expirationIsValid(token) == false then
        log_info("Token is expired.")
        goto out
    end

    -- 5. Verify the issuer
    if issuer ~= nil and issuerIsValid(token, issuer) == false then
        log_info("Issuer not valid.")
        goto out
    end

    -- 6. Verify the audience
    if audience ~= nil and audienceIsValid(token, audience) == false then
        log_info("Audience not valid.")
        goto out
    end

    -- 7. Add custom values from payload to variable
    if token.payloaddecoded.custom ~= nil then
        for name, payload in pairs(token.payloaddecoded.custom) do
            local clean_name = name:gsub("%W","_")
            local clean_value = payload
            if (type(payload) == 'table') then
                clean_value = table.concat(payload, ',')
            end

            txn.set_var(txn, "txn."..clean_name, clean_value)
            log_debug("txn."..clean_name.." is defined from payload")
        end
    end

    -- 8. Set authorized variable
    log_debug("req.authorized = true")
    txn.set_var(txn, "txn.authorized", true)

    -- exit
    do return end

    ::out::
    log_debug("req.authorized = false")
    txn.set_var(txn, "txn.authorized", false)
end

-- This function runs in the background similarly to a cronjob
-- On a high level it tries to get the public key from our jwks url
-- based on an interval. The interval we use is based on the cache headers as part of the JWKS response
function refresh_jwks()
    log_notice("Refresh JWKS task initialized")

    while true do
        log_notice('Refreshing JWKS data')
        local status, publicKeys = xpcall(getJwksData, debug.traceback, config.jwks_url)
        if status then
            config.publicKeys = publicKeys
        else
            local err = publicKeys
            log_alert("Unable to set public keys: "..tostring(err))
        end

        log_notice('Getting new Certificate in '..(config.publicKeys.expiresIn)..' seconds - '
                ..os.date('%c', os.time() + config.publicKeys.expiresIn))
        core.sleep(config.publicKeys.expiresIn)
    end
end

-- Called after the configuration is parsed.
-- Loads the OAuth public key for validating the JWT signature.
core.register_init(function()
    config.issuer = os.getenv("OAUTH_ISSUER")
    config.jwks_url = os.getenv("OAUTH_JWKS_URL")
    log_notice("JWKS URL: " .. (config.jwks_url or "<none>"))
    log_notice("Issuer: " .. (config.issuer or "<none>"))
end)

-- Called on a request.
core.register_action('jwtverify', {'http-req'}, jwtverify, 0)

-- Task is similar to a cronjob
core.register_task(refresh_jwks)