#!/usr/bin/env bash
DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="$HOME/.local/bin"
mkdir -p "$TARGET_DIR"
cp "$DIR/pocan" "$TARGET_DIR/pocan"
chmod +x "$TARGET_DIR/pocan"
echo "Installed pocan to $TARGET_DIR/pocan"
