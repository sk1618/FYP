#!/bin/bash
# sync.sh — pushes latest backend + frontend source to the Kali VM.
# Run this from the project root after any code change:
#   ./sync.sh

VM="amine@192.168.64.2"
PROJECT="/Users/aminwehbe/Desktop/FYP-Overhaul"

echo "Syncing backend..."
rsync -av --exclude='node_modules' --exclude='.env' \
  "$PROJECT/fyp-backend/" "$VM:~/fyp-backend/"

echo "Syncing frontend..."
rsync -av --exclude='node_modules' --exclude='.env' \
  "$PROJECT/fyp-frontend/" "$VM:~/fyp-frontend/"

echo "Done. Restart the backend (node src/server.js) to pick up changes."
echo "Refresh the browser for frontend changes."
