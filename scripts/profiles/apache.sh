# Apache httpd, from the Debian package.
#
# Not the official httpd image: that one builds from source into
# /usr/local/apache2, and the profile's /usr/sbin/apachectl is the path the
# Debian and Red Hat packages use. Verifying absolute paths against a layout
# no packaged host has would verify nothing.
PORT=443
VERSION_CMD="/usr/sbin/apachectl -v 2>&1"

DOCKERFILE='FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends apache2 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && a2enmod ssl \
 && a2dissite 000-default
COPY tls.conf /etc/apache2/sites-available/tls.conf
RUN a2ensite tls
CMD ["/usr/sbin/apachectl", "-D", "FOREGROUND"]'

bootstrap_config() {
    local dir="$1"
    mkdir -p "$dir/live/$NAME"
    cp "$dir/boot/fullchain.pem" "$dir/live/$NAME/fullchain.pem"
    cp "$dir/boot/key.pem"       "$dir/live/$NAME/privkey.pem"
    # In the build context, because a2ensite has to see it at build time.
    cat > "$dir/tls.conf" <<CONF
<VirtualHost *:443>
    ServerName $NAME
    SSLEngine on
    SSLCertificateFile    /etc/certpilot/live/$NAME/fullchain.pem
    SSLCertificateKeyFile /etc/certpilot/live/$NAME/privkey.pem
    DocumentRoot /var/www/html
</VirtualHost>
CONF
}
