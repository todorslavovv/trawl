#!/usr/bin/env bash
# Deploy the working tree to the Steam Deck. Run from the repository root on the PC.
# Code goes to ~/trawl (replaced), data lives in ~/trawl-data (never touched here).
set -euo pipefail
HOST="${1:-deck@steamdeck-1}"
rsync -az --delete --exclude '.git' --exclude 'data/' --exclude '__pycache__' \
      --exclude '.pytest_cache' ./ "$HOST:trawl/"
ssh "$HOST" 'mkdir -p ~/trawl-data && chmod 700 ~/trawl-data &&
  cp ~/trawl/deploy/trawl-*.service ~/trawl/deploy/trawl-*.timer ~/.config/systemd/user/ &&
  systemctl --user daemon-reload && echo deployed'
