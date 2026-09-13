# MariaDB, from the Debian package rather than the official image.
#
# The package is what gives root the unix_socket authentication plugin, and
# that is what makes the profile's reload — `mariadb -e "FLUSH SSL"` — work as
# root with no password anywhere. The official image sets a root password
# instead, so verifying against it would verify a reload no packaged host runs.
PORT=3306
STARTTLS="mysql"
VERSION_CMD="/usr/sbin/mariadbd --version 2>&1"
MOUNT_LIVE=0
# The handshake runs inside the container: OpenSSL 3.6 on the host rejects
# MariaDB's greeting ("Only MySQL protocol version 10 is supported") where
# OpenSSL 3.0 in the image reads it fine. The server is serving correctly
# either way; it is the test tool that disagrees.
PROBE_IN_CONTAINER=1

DOCKERFILE='FROM debian:12-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends mariadb-server ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY live /etc/certpilot/live
RUN chown -R mysql:mysql /etc/certpilot/live \
 && chmod 600 /etc/certpilot/live/*/privkey.pem \
 && printf "[mariadbd]\nssl_cert = /etc/certpilot/live/verify.certpilot.test/fullchain.pem\nssl_key  = /etc/certpilot/live/verify.certpilot.test/privkey.pem\nbind-address = 0.0.0.0\n" > /etc/mysql/mariadb.conf.d/60-ssl.cnf \
 && mariadb-install-db --user=mysql --datadir=/var/lib/mysql >/dev/null
# /run is a tmpfs recreated at container start, so the socket directory has to
# be made then rather than at build time.
CMD ["sh", "-c", "mkdir -p /run/mysqld && chown mysql:mysql /run/mysqld && exec /usr/sbin/mariadbd --user=mysql"]'

bootstrap_config() {
    local dir="$1"
    mkdir -p "$dir/live/$NAME"
    cp "$dir/boot/fullchain.pem" "$dir/live/$NAME/fullchain.pem"
    cp "$dir/boot/key.pem"       "$dir/live/$NAME/privkey.pem"
}
