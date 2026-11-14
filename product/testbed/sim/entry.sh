#!/bin/sh
# Network noise per container (tc netem): delay / jitter / loss, e.g. NETEM="delay 8ms 4ms distribution normal loss 0.2%"
if [ -n "$NETEM" ]; then tc qdisc replace dev eth0 root netem $NETEM || echo "netem not applied (needs NET_ADMIN)"; fi
exec "$@"
