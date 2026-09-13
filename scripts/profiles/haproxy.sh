# HAProxy, from the Debian package.
#
# The reload is the honest part of this one. The profile ships
# `systemctl reload haproxy`, because HAProxy has no in-process reload of its
# own — the seamless one hands the listening sockets to a new process, and on a
# packaged host systemd is what holds them. A container has no systemd, so what
# runs here is the signal systemd's own unit sends: Debian's haproxy.service
# has `ExecReload=/bin/kill -USR2 $MAINPID`, and haproxy here is PID 1 in
# master-worker mode. Same mechanism, different way of finding the pid.
#
# procps is in the image because debian:12-slim has no kill(1) — only bash's
# builtin, which an exec'd argv cannot reach. A normal Debian host has it; a
# slim base image is not a normal Debian host.
PORT=443
VERSION_CMD="/usr/sbin/haproxy -v 2>&1"
reload_override='["/bin/kill", "-USR2", "1"]'

DOCKERFILE='FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends haproxy ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*
COPY haproxy.cfg /etc/haproxy/haproxy.cfg
CMD ["/usr/sbin/haproxy", "-W", "-db", "-f", "/etc/haproxy/haproxy.cfg"]'

bootstrap_config() {
    local dir="$1"
    mkdir -p "$dir/live/$NAME"
    # One file: certificate, chain, key. The layout the profile writes, and the
    # only one `bind … ssl crt` reads.
    cp "$dir/boot/combined.pem" "$dir/live/$NAME/haproxy.pem"
    cat > "$dir/haproxy.cfg" <<CONF
global
    log stdout format raw local0

defaults
    mode http
    timeout connect 5s
    timeout client  10s
    timeout server  10s

frontend tls
    bind :443 ssl crt /etc/certpilot/live/$NAME/haproxy.pem
    http-request return status 200 content-type text/plain string "ok"
CONF
}
