# Tomcat, from the official image — a PKCS#12 keystore rather than PEM.
#
# The reload is the honest part. A packaged host restarts the service, and the
# profile says `systemctl restart tomcat10`; a container cannot, because the
# service is PID 1 and stopping it ends the container. So Tomcat is started in
# the background here and the reload is catalina.sh stop/start — the same
# operation the unit performs, arranged so something is left alive to perform
# it.
PORT=8443
VERSION_CMD="/usr/local/tomcat/bin/version.sh 2>/dev/null | grep 'Server version'"
MOUNT_LIVE=0
SPEC_EXTRA=',
      "keystore_password": "verify-only"'
# JAVA_HOME is set explicitly because the agent runs check and reload with a
# deliberately bare environment — PATH and nothing else, so that a reload
# command cannot read the enrolment token that put the agent's own environment
# together. catalina.sh needs JAVA_HOME and will not guess. On a packaged host
# this is invisible: the systemd unit sets it.
reload_override='["/bin/sh", "-c", "export JAVA_HOME=/opt/java/openjdk; /usr/local/tomcat/bin/shutdown.sh 2>/dev/null; sleep 2; exec /usr/local/tomcat/bin/startup.sh"]'

DOCKERFILE='FROM tomcat:10-jdk21
COPY live /etc/certpilot/live
COPY server.xml /usr/local/tomcat/conf/server.xml
CMD ["sh", "-c", "/usr/local/tomcat/bin/startup.sh && sleep infinity"]'

bootstrap_config() {
    local dir="$1"
    mkdir -p "$dir/live/$NAME"
    # The bootstrap keystore, built with the JDK's own tooling rather than by
    # this project's code — so what Tomcat reads at startup is known-good and
    # the only thing under test afterwards is what the agent wrote.
    openssl pkcs12 -export \
        -inkey "$dir/boot/key.pem" -in "$dir/boot/cert.pem" -certfile "$dir/boot/chain.pem" \
        -name tomcat -passout pass:verify-only \
        -out "$dir/live/$NAME/keystore.p12" >/dev/null 2>&1

    cat > "$dir/server.xml" <<CONF
<?xml version="1.0" encoding="UTF-8"?>
<Server port="8005" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="50" SSLEnabled="true">
      <SSLHostConfig>
        <Certificate certificateKeystoreFile="/etc/certpilot/live/$NAME/keystore.p12"
                     certificateKeystorePassword="verify-only"
                     certificateKeystoreType="PKCS12" />
      </SSLHostConfig>
    </Connector>
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps" unpackWARs="true" autoDeploy="true" />
    </Engine>
  </Service>
</Server>
CONF
}
