# Dovecot, from the Debian package. Port 993 — implicit TLS, no STARTTLS.
PORT=993
VERSION_CMD="/usr/sbin/dovecot --version 2>&1"

DOCKERFILE='FROM debian:12-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends dovecot-imapd ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY live /etc/certpilot/live
RUN printf "ssl = yes\nssl_cert = </etc/certpilot/live/verify.certpilot.test/fullchain.pem\nssl_key = </etc/certpilot/live/verify.certpilot.test/privkey.pem\n" > /etc/dovecot/conf.d/10-ssl.conf \
 && printf "mail_location = maildir:/var/mail/%%u\n" > /etc/dovecot/conf.d/99-mail.conf
CMD ["/usr/sbin/dovecot", "-F"]'

bootstrap_config() {
    local dir="$1"
    mkdir -p "$dir/live/$NAME"
    cp "$dir/boot/fullchain.pem" "$dir/live/$NAME/fullchain.pem"
    cp "$dir/boot/key.pem"       "$dir/live/$NAME/privkey.pem"
}
