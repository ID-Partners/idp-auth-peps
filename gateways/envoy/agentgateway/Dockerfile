# agentgateway (solo.io) image for the demo — the alternative gateway to Kong.
#
# The upstream image is a distroless (no shell) chainguard base, so we re-plate
# the /app/agentgateway binary onto debian-slim (trixie: the binary needs
# glibc >= 2.39) to run a small entrypoint that renders config.yaml from its
# template (substituting the upstream hosts that differ between docker-compose
# and Railway) before starting the gateway.
#
# The AuthZEN PEP itself lives in the sibling authzen-ext/ service, attached in
# config.yaml via the Envoy-compatible extAuthz policy.
FROM ghcr.io/agentgateway/agentgateway:v1.3.1 AS upstream

FROM debian:trixie-slim
COPY --from=upstream /app/agentgateway /app/agentgateway
COPY config.yaml.template /etc/agentgateway/config.yaml.template
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENV AGENTGATEWAY_ENV=container
EXPOSE 8000
ENTRYPOINT ["/docker-entrypoint.sh"]
