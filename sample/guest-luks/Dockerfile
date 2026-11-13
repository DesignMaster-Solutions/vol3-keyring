# Guest userland for the live LUKS sample: real cryptsetup, nothing else of ours.
FROM alpine:3.20
RUN apk add --no-cache cryptsetup device-mapper
COPY init /init
