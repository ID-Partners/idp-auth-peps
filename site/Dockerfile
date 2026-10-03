# The microsite at https://federated-enforcement.idpartners.global, as one nginx image:
# the landing page from site/public, and the one-page overview and the configuration
# reference from docs/, so the site is the documents' home. Railway builds it from the
# repository root on every push to main; so can you:
#
#   docker build -f site/Dockerfile -t federated-enforcement .
#   docker run --rm -p 8080:8080 federated-enforcement
#
# nginx-unprivileged runs as its own user and listens on ${PORT} (Railway sets it; 8080
# otherwise), which the entrypoint substitutes into the template. NGINX_ENVSUBST_FILTER
# keeps it from touching any other $name in there.
FROM nginxinc/nginx-unprivileged:1.31-alpine@sha256:26b0bf6fbf07297983cb341998d79c831508787de26627dd2a112321b9c3a4af
ENV PORT=8080 NGINX_ENVSUBST_FILTER=^PORT$
COPY site/nginx/default.conf.template /etc/nginx/templates/default.conf.template
COPY site/public/ /usr/share/nginx/html/
COPY docs/overview.html /usr/share/nginx/html/overview.html
COPY docs/reference/ /usr/share/nginx/html/docs/
EXPOSE 8080
