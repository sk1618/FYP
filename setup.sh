#!/bin/bash
set -e

echo "======================================"
echo "  FYP Dashboard — Setup Script"
echo "======================================"
echo ""

# ── 1. Node.js 20 ──────────────────────────────────────────────────────────────
if ! command -v node &>/dev/null || [[ $(node -v | cut -d. -f1 | tr -d 'v') -lt 18 ]]; then
  echo "[1/6] Installing Node.js 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash - > /dev/null 2>&1
  sudo apt install -y nodejs > /dev/null 2>&1
  echo "      Node.js $(node -v) installed."
else
  echo "[1/6] Node.js $(node -v) already installed. Skipping."
fi

# ── 2. MySQL ───────────────────────────────────────────────────────────────────
if ! command -v mysql &>/dev/null; then
  echo "[2/6] Installing MySQL..."
  sudo apt install -y mysql-server > /dev/null 2>&1
else
  echo "[2/6] MySQL already installed. Skipping."
fi

echo "      Starting MySQL service..."
sudo systemctl start mysql
sudo systemctl enable mysql > /dev/null 2>&1

# ── 3. Python dependencies ─────────────────────────────────────────────────────
echo "[3/6] Installing Python dependencies..."
pip3 install --quiet scikit-learn scapy pandas matplotlib joblib 2>/dev/null || \
  pip3 install --quiet --break-system-packages scikit-learn scapy pandas matplotlib joblib
echo "      Python dependencies installed."

# ── 4. Create DB + user ────────────────────────────────────────────────────────
echo "[4/6] Setting up MySQL database..."

DB_NAME="fyp_dashboard"
DB_USER="fyp_user"
DB_PASS="fyp_password123"

sudo mysql -e "
  CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`;
  CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
  GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
  FLUSH PRIVILEGES;
" 2>/dev/null

echo "      Loading schema..."
sudo mysql -u root "${DB_NAME}" < schema.sql

echo "      Database '${DB_NAME}' ready."

# ── 5. Create .env files ───────────────────────────────────────────────────────
echo "[5/6] Creating .env files..."

cat > fyp-backend/.env << EOF
DB_HOST=127.0.0.1
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASS}
DB_NAME=${DB_NAME}
PORT=3001
EOF

cat > fyp-frontend/.env << EOF
VITE_API_BASE_URL=http://localhost:3001
EOF

echo "      .env files created."

# ── 6. Lynis sudoers entry ─────────────────────────────────────────────────────
echo "[6/7] Configuring Lynis sudo access..."
CURRENT_USER=$(whoami)
SUDOERS_LINE="${CURRENT_USER} ALL=(ALL) NOPASSWD: /usr/sbin/lynis"
SUDOERS_FILE="/etc/sudoers.d/lynis"
if ! sudo grep -qF "$SUDOERS_LINE" "$SUDOERS_FILE" 2>/dev/null; then
  echo "$SUDOERS_LINE" | sudo tee "$SUDOERS_FILE" > /dev/null
  sudo chmod 440 "$SUDOERS_FILE"
  echo "      Lynis sudoers entry added for user '${CURRENT_USER}'."
else
  echo "      Lynis sudoers entry already present. Skipping."
fi

# ── 7. npm install ─────────────────────────────────────────────────────────────
echo "[7/7] Installing Node dependencies..."
(cd fyp-backend && npm install --silent)
(cd fyp-frontend && npm install --silent)
echo "      Dependencies installed."

# ── Done ───────────────────────────────────────────────────────────────────────
echo ""
echo "======================================="
echo "  Setup complete!"
echo "======================================="
echo ""
echo "  Start the backend:"
echo "    cd fyp-backend && npm run dev"
echo ""
echo "  Start the frontend (new terminal):"
echo "    cd fyp-frontend && npm run dev"
echo ""
echo "  Dashboard → http://localhost:5173"
echo "======================================"
