#!/usr/bin/env bash
set -euo pipefail

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

$SUDO apt update
$SUDO apt install -y pkg-config clang libclang-dev libgbm-dev libpipewire-0.3-dev libspa-0.2-dev libwayland-dev libegl1-mesa-dev libglvnd-dev
