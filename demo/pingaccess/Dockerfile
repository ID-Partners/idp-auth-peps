# syntax=docker/dockerfile:1
# PingAccess with the AuthZEN rule installed and a hook that wires it up, for the demo.
# Three stages: the SDK jar is taken from the public PingAccess image (it is on no Maven
# repository), the rule is built against it, and the result is dropped into a fresh
# PingAccess image's /opt/in, which the DevOps image copies into the instance at boot.
# Build from the repository root (demo/docker-compose.yml does):
#
#   docker build -f demo/pingaccess/Dockerfile -t idp-auth-peps-pingaccess .
#
# Running it needs a licence: PING_IDENTITY_DEVOPS_USER / _KEY and PING_IDENTITY_ACCEPT_EULA=YES.
ARG PA_IMAGE=pingidentity/pingaccess:9.1.0-latest

FROM ${PA_IMAGE} AS sdk

FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY --from=sdk /opt/server/lib/pingaccess-sdk-*.jar /pa/lib/
COPY gateways/pingaccess/authzen-pdp/pom.xml .
COPY gateways/pingaccess/authzen-pdp/src ./src
# The SDK version is whatever the image shipped; the pom's default is only a default.
RUN v=$(ls /pa/lib/pingaccess-sdk-*.jar | sed 's#.*/pingaccess-sdk-\(.*\)\.jar#\1#') \
    && echo "building against PingAccess SDK $v" \
    && mvn -q -B -Dpa.server.root=/pa -Dpa.sdk.version="$v" -DskipTests package \
    && ls target/*.jar

FROM ${PA_IMAGE}
# /opt/in is the DevOps image's local server profile: instance/ is merged into the
# running instance and hooks/ overrides the stock hooks by name.
COPY --from=build --chown=9031:0 /src/target/authzen-pdp-pingaccess-*.jar /opt/in/instance/deploy/
COPY --chown=9031:0 --chmod=755 demo/pingaccess/hooks/ /opt/in/hooks/
