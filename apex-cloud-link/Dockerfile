ARG BUILD_FROM=ghcr.io/hassio-addons/base:15.0.4
FROM ${BUILD_FROM}

# Add env
ENV LANG C.UTF-8

# Install tooling for config parsing and fleet reporting
RUN apk add --no-cache jq wget tar curl iproute2

RUN find /etc /package -path "*/base-addon-banner/up" -exec sh -c 'echo -e "#!/command/with-contenv bash\nexit 0" > "$1"' _ {} +

# Copy root filesystem
COPY rootfs /

# Make scripts executable
RUN chmod a+x /etc/s6-overlay/s6-rc.d/apex-cloud-link/run

# Force s6-overlay as the entrypoint explicitly so it always runs as PID 1
ENTRYPOINT ["/init"]
