FROM haproxy:2.8-alpine as builder

USER root
WORKDIR /tmp

RUN apk add --no-cache build-base gcc musl-dev lua5.3 lua5.3-dev make openssl-dev

RUN mkdir -p /usr/local/share/lua/5.3
RUN wget https://github.com/haproxytech/haproxy-lua-http/archive/master.tar.gz -O /tmp/haproxy-lua-http.tar.gz && \
    tar -xf /tmp/haproxy-lua-http.tar.gz -C /tmp && \
    cp /tmp/haproxy-lua-http-master/http.lua /usr/local/share/lua/5.3/http.lua
RUN wget https://github.com/rxi/json.lua/archive/v0.1.2.tar.gz -O /tmp/json-lua.tar.gz && \
    tar -xf /tmp/json-lua.tar.gz -C /tmp && \
    cp /tmp/json.lua-*/json.lua /usr/local/share/lua/5.3/json.lua
RUN wget https://github.com/diegonehab/luasocket/archive/master.tar.gz -O /tmp/luasocker.tar.gz && \
    tar -xf /tmp/luasocker.tar.gz -C /tmp && \
    cd /tmp/luasocket-master && \
    make clean all install-both LUAINC=/usr/include/lua5.3
RUN wget https://github.com/wahern/luaossl/archive/rel-20220711.tar.gz -O /tmp/rel.tar.gz && \
    tar -xf /tmp/rel.tar.gz -C /tmp && \
    cd /tmp/luaossl-rel-* && \
    make install

FROM haproxy:2.8-alpine

USER root
RUN apk add --no-cache ca-certificates lua5.3

COPY --from=builder /usr/local/share/lua/5.3 /usr/local/share/lua/5.3
COPY --from=builder /usr/local/lib/lua/5.3 /usr/local/lib/lua/5.3
COPY ./src/base64.lua ./src/jwtverify.lua /usr/local/share/lua/5.3/

USER haproxy
