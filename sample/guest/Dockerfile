# Guest userland (x86_64), built with --platform linux/amd64 and exported as an initramfs.
FROM alpine:3.20 AS build
RUN apk add --no-cache build-base linux-headers
COPY keyring_demo.c /src/
RUN gcc -O1 -static -pthread -Wall -Wextra -o /src/keyring_demo /src/keyring_demo.c

FROM alpine:3.20
RUN apk add --no-cache keyutils
COPY --from=build /src/keyring_demo /usr/local/bin/keyring_demo
# One name per role, so each process has its own comm; /sbin/request-key is the helper the kernel runs.
RUN cd /usr/local/bin && for n in alice bob orphan carol empty; do ln -s keyring_demo kr-$n; done \
 && ln -sf /usr/local/bin/keyring_demo /sbin/request-key
COPY init /init
