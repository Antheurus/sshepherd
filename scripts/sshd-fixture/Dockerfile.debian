# Disposable local Linux target for `just smoke` (see scripts/smoke.sh).
#
# Provides sshd plus the same toolset sshepherd's read-only ops assume on a real remote
# (coreutils, procps, iproute2, util-linux) and the docker CLI. The docker CLI here is
# client-only — no daemon runs inside this container. scripts/sshd-fixture/docker-compose.yml
# mounts the HOST's docker socket into this container (Docker-outside-of-Docker), so
# `services`/`logs docker`/`db` ops exec into the sibling `postgres`/`app` fixture
# containers exactly like they would on a real deploy host running docker compose.
#
# Not for production use: root SSH login is enabled (key-only, no password auth) purely
# so the docker socket is always reachable without fiddling with host-specific docker
# group GIDs. authorized_keys is bind-mounted at runtime by docker-compose.yml —
# scripts/smoke.sh generates a fresh ephemeral keypair per run; no key material is baked
# into this image.

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    coreutils \
    procps \
    iproute2 \
    util-linux \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# docker CLI only (no daemon) — talks to the host daemon via the mounted socket.
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker

RUN mkdir -p /run/sshd /root/.ssh \
  && chmod 700 /root/.ssh \
  && ssh-keygen -A \
  && { \
       echo 'PermitRootLogin prohibit-password'; \
       echo 'PubkeyAuthentication yes'; \
       echo 'PasswordAuthentication no'; \
       echo 'ChallengeResponseAuthentication no'; \
     } >> /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
