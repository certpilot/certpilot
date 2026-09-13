# PostgreSQL, from the official image.
#
# MOUNT_LIVE=0 here. PostgreSQL refuses to start when its key file is not owned
# by the account the server runs as — correctly, and it is one of the very few
# services that checks — so the bootstrap material is built into the image with
# the right ownership rather than bind-mounted from a host whose uids are not
# the container's.
PORT=5432
STARTTLS="postgres"
VERSION_CMD="postgres --version 2>&1"
MOUNT_LIVE=0
reload_override='["/bin/kill", "-HUP", "1"]'
CMD_ARGS="-c ssl=on -c ssl_cert_file=/etc/certpilot/live/verify.certpilot.test/fullchain.pem -c ssl_key_file=/etc/certpilot/live/verify.certpilot.test/privkey.pem"

DOCKERFILE='FROM postgres:16
COPY live /etc/certpilot/live
RUN chown -R postgres:postgres /etc/certpilot/live \
 && chmod 600 /etc/certpilot/live/*/privkey.pem'

bootstrap_config() {
    local dir="$1"
    mkdir -p "$dir/live/$NAME"
    cp "$dir/boot/fullchain.pem" "$dir/live/$NAME/fullchain.pem"
    cp "$dir/boot/key.pem"       "$dir/live/$NAME/privkey.pem"
}

container_args() {
    echo "-e POSTGRES_PASSWORD=verify -e POSTGRES_HOST_AUTH_METHOD=trust"
}
