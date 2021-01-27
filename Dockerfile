FROM haproxy:1.9

WORKDIR /root

# hadolint ignore=DL3003
RUN apt-get update && \
    apt-get install lua5.3 liblua5.3-dev wget make libssl-dev -y && \
    mkdir -p /usr/local/share/lua/5.3 && \
    #haproxy-lua-http
    wget https://github.com/haproxytech/haproxy-lua-http/archive/master.tar.gz && \
    tar -xf master.tar.gz -C /usr/local/share/lua/5.3 && \
    ln -s /usr/local/share/lua/5.3/haproxy-lua-http-master/http.lua /usr/local/share/lua/5.3/http.lua && \
    rm /root/master.tar.gz && \
    #json.lua
    wget https://github.com/rxi/json.lua/archive/v0.1.2.tar.gz && \
    tar -xf v0.1.2.tar.gz -C /usr/local/share/lua/5.3 && \
    ln -s /usr/local/share/lua/5.3/json.lua-0.1.2/json.lua /usr/local/share/lua/5.3/json.lua && \
    rm /root/v0.1.2.tar.gz && \
    #luasocket
    wget https://github.com/diegonehab/luasocket/archive/master.tar.gz && \
    tar -xf master.tar.gz -C /usr/local/share/lua/5.3 && \
    cd /usr/local/share/lua/5.3/luasocket-master && \
    make clean all install-both LUAINC=/usr/include/lua5.3 && \
    rm /root/master.tar.gz && \
    #luaossl
    cd /root && \
    wget https://github.com/wahern/luaossl/archive/rel-20190731.tar.gz && \
    tar -xf rel-20190731.tar.gz -C /usr/local/share/lua/5.3 && \
    cd /usr/local/share/lua/5.3/luaossl-rel-20190731 && \
    make install && \
    rm /root/rel-20190731.tar.gz

COPY ./src/base64.lua /usr/local/share/lua/5.3
COPY ./src/jwtverify.lua /usr/local/share/lua/5.3