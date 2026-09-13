# Postfix, from the Debian package.
#
# Port 25 with STARTTLS, which is the configuration an estate actually runs:
# submission on 587 and smtps on 465 exist, but the certificate a mail server
# presents to other mail servers is the one on 25, and it is the one nobody is
# tracking.
PORT=25
STARTTLS="smtp"
VERSION_CMD="/usr/sbin/postconf mail_version 2>&1"

DOCKERFILE='FROM debian:12-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends postfix ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY live /etc/certpilot/live
RUN cp /usr/share/postfix/main.cf.debian /etc/postfix/main.cf \
 && postconf -e "myhostname = verify.certpilot.test" \
 && postconf -e "smtpd_tls_cert_file = /etc/certpilot/live/verify.certpilot.test/fullchain.pem" \
 && postconf -e "smtpd_tls_key_file = /etc/certpilot/live/verify.certpilot.test/privkey.pem" \
 && postconf -e "smtpd_tls_security_level = may" \
 && postconf -e "maillog_file = /dev/stdout" \
 && newaliases
CMD ["/usr/sbin/postfix", "start-fg"]'

bootstrap_config() {
    local dir="$1"
    mkdir -p "$dir/live/$NAME"
    cp "$dir/boot/fullchain.pem" "$dir/live/$NAME/fullchain.pem"
    cp "$dir/boot/key.pem"       "$dir/live/$NAME/privkey.pem"
}
