#!/bin/bash
# sync.sh — pushes latest source to the Kali VM.
# Run this from the Final Year Project root:
#   ./sync.sh

VM="amine@192.168.64.2"
PROJECT="/Users/aminwehbe/Desktop/University/Final Year Project"

echo "Syncing backend..."
rsync -av --exclude='node_modules' --exclude='.env' \
  "$PROJECT/fyp-backend/" "$VM:~/fyp-backend/"

echo "Syncing frontend..."
rsync -av --exclude='node_modules' --exclude='.env' \
  "$PROJECT/fyp-frontend/" "$VM:~/fyp-frontend/"

echo ""
echo "Done."
echo "  cd ~/fyp-backend && npm run dev"
echo "  cd ~/fyp-frontend && npm run dev"
