# SETUP.md

## Running on Kali Linux VM (Recommended)

### Prerequisites
- Git installed
- Internet connection

### Steps

```bash
git clone https://github.com/sk1618/FYP.git
cd FYP
git checkout Amine-Branch
chmod +x setup.sh && ./setup.sh
```

Then open two terminals:

**Terminal 1 — Backend:**
```bash
cd fyp-backend && npm run dev
```

**Terminal 2 — Frontend:**
```bash
cd fyp-frontend && npm run dev
```

Dashboard → `http://localhost:5173`

The setup script handles everything: Node.js, MySQL, Python dependencies, database creation, schema, `.env` files, and `npm install`.

---

## Running on Mac / Windows

The `setup.sh` script is Linux-only. You'll need to do the following manually.

### 1. Install dependencies

| Dependency | Mac | Windows |
|---|---|---|
| Node.js 18+ | [nodejs.org](https://nodejs.org) or `brew install node` | [nodejs.org](https://nodejs.org) |
| MySQL 8.0 | `brew install mysql` | [mysql.com/downloads](https://dev.mysql.com/downloads/installer/) |
| Python 3 | Pre-installed or `brew install python` | [python.org](https://python.org) |
| Nmap | `brew install nmap` | [nmap.org/download](https://nmap.org/download.html) |
| Metasploit | `brew install metasploit` | Not recommended on Windows |

### 2. Python dependencies

```bash
pip3 install scikit-learn scapy pandas matplotlib joblib
```

### 3. MySQL — create the database

```sql
CREATE DATABASE fyp_dashboard;
CREATE USER 'fyp_user'@'localhost' IDENTIFIED BY 'fyp_password123';
GRANT ALL PRIVILEGES ON fyp_dashboard.* TO 'fyp_user'@'localhost';
FLUSH PRIVILEGES;
```

Then load the schema:
```bash
mysql -u fyp_user -p fyp_dashboard < schema.sql
```

### 4. Backend `.env`

Create `fyp-backend/.env`:
```
DB_HOST=127.0.0.1
DB_USER=fyp_user
DB_PASSWORD=fyp_password123
DB_NAME=fyp_dashboard
PORT=3001
```

### 5. Frontend `.env`

Create `fyp-frontend/.env`:
```
VITE_API_BASE_URL=http://localhost:3001
```

### 6. Install and run

```bash
cd fyp-backend && npm install && npm run dev
```
```bash
cd fyp-frontend && npm install && npm run dev
```

### What needs to change on Mac/Windows

| Issue | Detail |
|---|---|
| **Tool Runner** | Nmap works on Mac/Windows. Metasploit is unreliable on Windows — that feature may not work. |
| **Python command** | On Windows, `python3` may need to be changed to `python` in `fyp-backend/src/routes/ai.js` |
| **Nmap path** | If Nmap isn't on your PATH, update the command in `fyp-backend/src/utils/toolRunner.js` |
