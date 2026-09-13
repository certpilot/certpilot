# Caddy, from the official image — which puts the binary at /usr/bin/caddy,
# the same place the Debian package from Caddy's own repository does.
PORT=443
VERSION_CMD="/usr/bin/caddy version 2>&1"
IMAGE="caddy:2-alpine"

bootstrap_config() {
    local dir="$1"
    mkdir -p "$dir/live/$NAME" "$dir/conf"
    cp "$dir/boot/fullchain.pem" "$dir/live/$NAME/fullchain.pem"
    cp "$dir/boot/key.pem"       "$dir/live/$NAME/privkey.pem"
    # auto_https off, because the entire reason to give Caddy a certificate is
    # that this estate's CA is not a public one and Caddy must not go looking
    # for its own.
    cat > "$dir/conf/Caddyfile" <<CONF
{
    auto_https off
    admin localhost:2019
}

https://$NAME:443 {
    tls /etc/certpilot/live/$NAME/fullchain.pem /etc/certpilot/live/$NAME/privkey.pem
    respond "ok"
}
CONF
}

container_args() {
    echo "-v $1/conf/Caddyfile:/etc/caddy/Caddyfile:ro"
}
