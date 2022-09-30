FROM alpine:3.16.2 as modsecurity-build

ARG MODSECURITY_VERSION=v3.0.6

RUN apk update \
    && apk upgrade \
    && apk add --no-cache ca-certificates openssl \
    && update-ca-certificates \
    && apk add --no-cache --virtual .build-deps \
       ca-certificates  \
       gcc              \
       g++              \
       pcre-dev         \
       make             \
       automake         \
       autoconf         \
       byacc            \
       flex             \
       libstdc++        \
       libxml2-dev      \
       geoip-dev        \
       lmdb-dev         \
       libtool          \
       linux-headers    \
       git              

RUN mkdir -p /etc/nginx/modsecurity.d/ \
    && mkdir -p /usr/src \
    && cd /usr/src \
    && git clone --recursive --branch $MODSECURITY_VERSION --single-branch https://github.com/SpiderLabs/ModSecurity.git \
    && MODSECURITY_COMMIT=$(git --git-dir=/usr/src/ModSecurity/.git rev-parse --short HEAD) \
    && echo $MODSECURITY_COMMIT > /tmp/modseccommit \
    && cd /usr/src/ModSecurity \
    && git submodule init \
    && git submodule update \
    && ./build.sh \
    && ./configure \
        --with-lmdb          \
        --with-geoip=yes     \
        --enable-examples=no \
    && make \
    && make install \
    && install -m444 /usr/src/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsecurity.d/modsecurity.conf \
    && install -m444 /usr/src/ModSecurity/unicode.mapping /etc/nginx/modsecurity.d/unicode.mapping 

RUN strip /usr/local/modsecurity/bin/* \
    && strip /usr/local/modsecurity/lib/*.a \
    && strip /usr/local/modsecurity/lib/*.so.* \
    && apk del .build-deps \
    && rm -rf /usr/src \
    && rm -rf /var/cache/apk/*

FROM alpine:3.16.2 as nginx-build

ARG NGINX_VERSION=1.23.1
ARG MODSECURITY_CONNECTOR_VERSION=v1.0.3
ARG CRS_VERSION=3.3.2

ARG BUILD_DATE
ARG VCS_REF

COPY --from=modsecurity-build /usr/local/modsecurity/ /usr/local/modsecurity/

COPY --from=modsecurity-build /tmp/modseccommit /tmp/modseccommit

RUN apk update \
    && apk upgrade \
    && apk add --no-cache ca-certificates openssl \
    && update-ca-certificates \
    && apk add --no-cache --virtual .build-deps \
       gcc              \
       g++              \
       libc-dev         \
       make             \
       pcre-dev         \
       zlib-dev         \
       linux-headers    \
       libxslt-dev      \
       libressl-dev     \
       lmdb-dev         \
       libmaxminddb-dev \
       gd-dev           \
       geoip-dev        \
       yajl-dev         \
       perl-dev         \
       file             \
       git              \
       wget

RUN mkdir -p /usr/src \
    && cd /usr/src \
    && git clone --depth=1 --recursive --shallow-submodules --branch $MODSECURITY_CONNECTOR_VERSION --single-branch https://github.com/SpiderLabs/ModSecurity-nginx.git \
    && git clone --depth=1 --recursive --shallow-submodules https://github.com/openresty/headers-more-nginx-module \
    && git clone --depth=1 --recursive --shallow-submodules https://github.com/AirisX/nginx_cookie_flag_module \
    && git clone --depth=1 --recursive --shallow-submodules https://github.com/google/ngx_brotli \
    && git clone --depth=1 https://github.com/coreruleset/coreruleset /usr/local/share/coreruleset \
    && CRS_COMMIT=$(git --git-dir=/usr/local/share/coreruleset/.git rev-parse --short HEAD) \
    && MODSECURITY_COMMIT=$(cat /tmp/modseccommit) \
    && cp /usr/local/share/coreruleset/crs-setup.conf.example /usr/local/share/coreruleset/crs-setup.conf \
    && find /usr/local/share/coreruleset \! -name '*.conf' -type f -mindepth 1 -maxdepth 1 -delete \
    && find /usr/local/share/coreruleset \! -name 'rules' -type d -mindepth 1 -maxdepth 1 | xargs rm -rf \
    && wget -qO nginx.tar.gz https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz \
    && tar -zxC /usr/src -f nginx.tar.gz \
    && rm nginx.tar.gz \
    && cd /usr/src/nginx-$NGINX_VERSION \
    && ./configure \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --modules-path=/usr/lib/nginx/modules \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --http-log-path=/var/log/nginx/access.log \
        --pid-path=/var/run/nginx.pid \
        --lock-path=/var/lock/nginx.lock \
        --http-client-body-temp-path=/var/cache/nginx/client_temp \
        --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
        --user=nginx \
        --group=nginx \
        --with-pcre-jit \
        --with-file-aio \
        --with-threads \
        --with-http_addition_module \
        --with-http_auth_request_module \
        --with-http_geoip_module=dynamic \
        --with-http_gunzip_module \
        --with-http_gzip_static_module \
        --with-http_random_index_module \
        --with-http_realip_module \
        --with-http_slice_module \
        --with-http_ssl_module \
        --with-http_sub_module \
        --with-http_stub_status_module \
        --with-http_v2_module \
        --with-http_secure_link_module \
        --with-stream \
        --with-stream_ssl_module \
        --with-stream_ssl_preread_module \
        --with-stream_realip_module \
        --with-stream_geoip_module=dynamic \
        --add-module=/usr/src/ModSecurity-nginx \
        --add-module=/usr/src/ngx_brotli \
        --add-module=/usr/src/headers-more-nginx-module \
        --add-module=/usr/src/nginx_cookie_flag_module \
        --with-cc-opt='-g -O2 -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC' \
        --with-ld-opt='-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie' \
        --with-http_dav_module \
        --build="nginx-waf-$VCS_REF-$BUILD_DATE ModSecurity-$MODSECURITY_COMMIT ModSecurity-nginx-$(git --git-dir=/usr/src/ModSecurity-nginx/.git rev-parse --short HEAD) coreruleset-$CRS_COMMIT ngx_brotli-$(git --git-dir=/usr/src/ngx_brotli/.git rev-parse --short HEAD) headers-more-nginx-module-$(git --git-dir=/usr/src/headers-more-nginx-module/.git rev-parse --short HEAD) nginx_cookie_flag_module-$(git --git-dir=/usr/src/nginx_cookie_flag_module/.git rev-parse --short HEAD)" \
    && make \
    && make install \  
    && make modules

RUN strip /usr/sbin/nginx* \
    && strip /usr/lib/nginx/modules/*.so \
    && apk del .build-deps \
    && rm -rf /usr/src \
    && rm -rf /tmp/* \
    && rm -rf /var/cache/apk/*

FROM alpine:3.16.2

COPY --from=modsecurity-build /usr/local/modsecurity/ /usr/local/modsecurity/

COPY --from=modsecurity-build /etc/nginx/modsecurity.d /etc/nginx/modsecurity.d

COPY --from=nginx-build /usr/local/share/coreruleset /usr/local/share/coreruleset/

COPY --from=nginx-build /usr/lib/nginx/modules /usr/lib/nginx/modules

COPY --from=nginx-build /usr/sbin/nginx /usr/sbin/nginx

COPY --from=nginx-build /etc/nginx /etc/nginx

COPY conf/conf.d /etc/nginx/conf.d

RUN apk update \
    && apk upgrade \
    && apk add --no-cache \
       pcre             \
       libxml2          \
       yajl             \
       geoip            \
       libstdc++        \
       libmaxminddb     \
       lmdb             \
       libressl         \
    && mkdir -p /var/log/nginx \
    && mkdir -p /var/cache/nginx \
    && addgroup -g 1001 -S nginx \
    && adduser -D -S -H -u 1001 -h /var/cache/nginx -s /sbin/nologin -G nginx -g nginx nginx \
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log

RUN touch /etc/nginx/modsecurity.d/include.conf \
    && echo "include /etc/nginx/modsecurity.d/modsecurity.conf" >> /etc/nginx/modsecurity.d/include.conf \
    && echo "include /usr/local/share/coreruleset/crs-setup.conf" >> /etc/nginx/modsecurity.d/include.conf \
    && echo "include /usr/local/share/coreruleset/rules/*.conf" >> /etc/nginx/modsecurity.d/include.conf

STOPSIGNAL SIGTERM

CMD ["/usr/sbin/nginx", "-g", "daemon off;"]