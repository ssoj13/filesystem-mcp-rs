#!/usr/bin/env bash
set -euo pipefail

sudo apt update
sudo apt install -y pkg-config libpipewire-0.3-dev libspa-0.2-dev
