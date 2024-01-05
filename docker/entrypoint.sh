#!/bin/bash
set -e
echo "Container's IP address: `awk 'END{print $1}' /etc/hosts`"

if [ "$1" = 'server' ]; then
   /root/.local/bin/poetry run jupyter-lab --port=8081 --no-browser --ip=0.0.0.0 --allow-root
else
    exec "$@"
fi
