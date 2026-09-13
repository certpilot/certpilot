# nginx, from the official image.
#
# The server block names fullchain.pem, which is the thing the profile's first
# note is about: nginx does not read a chain from anywhere else and does not
# build one, so a configuration pointing at cert.pem serves the leaf alone.
# Verifying against fullchain.pem is verifying the advice.
IMAGE="nginx:1.27-alpine"
PORT=443
VERSION_CMD="nginx -v 2>&1"

bootstrap_config() {
    local dir="$1"
    mkdir -p "$dir/live/$NAME" "$dir/conf"
    cp "$dir/boot/fullchain.pem" "$dir/live/$NAME/fullchain.pem"
    cp "$dir/boot/key.pem"       "$dir/live/$NAME/privkey.pem"
    cat > "$dir/conf/tls.conf" <<CONF
server {
    listen 443 ssl;
    server_name $NAME;

    ssl_certificate     /etc/certpilot/live/$NAME/fullchain.pem;
    ssl_certificate_key /etc/certpilot/live/$NAME/privkey.pem;

    location / { return 200 "ok\n"; }
}
CONF
}

container_args() {
    echo "-v $1/conf/tls.conf:/etc/nginx/conf.d/tls.conf:ro"
}
