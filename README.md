# Cybersecurity Monitoring Dashboard — FYP

A full-stack cybersecurity monitoring dashboard built as a Final Year Project. It provides real-time network threat visibility through automated scanning, vulnerability tracking, and ML-based PCAP analysis — all in a dark, purpose-built UI.

---

## Features

- **Live Alerts Table** — view, filter, search, and delete network alerts with severity badges
- **Vulnerabilities Table** — track detected vulnerabilities with per-row delete and filtering
- **Tool Runner** — run Nmap, Metasploit, Nikto, Lynis, Hydra, or SQLMap against a target directly from the dashboard
- **AI PCAP Analyzer** — upload a `.pcap` file and get a Random Forest ML classification of attack traffic
- **Summary Cards** — at-a-glance counts for total alerts, high/medium/low severity, and vulnerabilities
- **Auto-Refresh** — data refreshes every 30 seconds with a live countdown; can be toggled on/off
- **CSV Export** — export filtered alerts or vulnerabilities to a `.csv` file with one click
- **Confirm Modal** — native-looking confirmation dialog before any destructive delete action

---

## Tech Stack

| Layer    | Technology                          |
|----------|-------------------------------------|
| Frontend | React 19, Vite 7, Axios             |
| Backend  | Node.js, Express 5, mysql2/promise  |
| Database | MySQL 8.0                           |
| ML Model | Python 3, scikit-learn (Random Forest) |
| Tools    | Nmap, Metasploit (msfconsole), Nikto, Lynis, Hydra, SQLMap |

---

## Project Structure

```
FYP-Overhaul/
├── fyp-backend/
│   ├── src/
│   │   ├── server.js               # Entry point, loads env
│   │   ├── app.js                  # Express app, middleware, routes
│   │   ├── db.js                   # mysql2/promise pool
│   │   ├── routes/
│   │   │   ├── alerts.js           # CRUD for alerts
│   │   │   ├── vulnerabilities.js  # CRUD for vulnerabilities
│   │   │   ├── tools.js            # Nmap / Metasploit trigger
│   │   │   └── ai.js               # PCAP upload + ML analysis
│   │   ├── controllers/
│   │   │   └── toolController.js   # Scan orchestration + DB persistence
│   │   └── utils/
│   │       ├── toolRunner.js       # child_process.spawn wrapper
│   │       ├── vuln.js             # Shared vulnerability auto-creation
│   │       └── response.js         # Standardised JSON envelope helpers
│   └── ai/
│       ├── analyze_ai.py           # Python ML script (Random Forest)
│       └── rf_model.pkl            # Trained model
│
├── fyp-frontend/
│   └── src/
│       ├── App.jsx                 # Root component, data fetching, auto-refresh
│       ├── index.css               # Full design system (CSS custom properties)
│       └── components/
│           ├── AlertsTable.jsx
│           ├── VulnerabilitiesTable.jsx
│           ├── SummaryCards.jsx
│           ├── ToolRunner.jsx
│           └── PcapAnalyzer.jsx
│
└── sync.sh                         # rsync helper to push changes to Kali VM
```

---

## Setup

### Prerequisites

- Node.js 18+
- MySQL 8.0 running and accessible
- Python 3 with `scikit-learn`, `scapy`, `pandas` installed
- Nmap, Metasploit, Nikto, Lynis, Hydra, and SQLMap installed (pre-installed on Kali Linux)

### 1. Clone the repo

```bash
git clone https://github.com/sk1618/FYP.git
cd FYP
git checkout Main-Branch
```

### 2. Backend

```bash
cd fyp-backend
npm install
```

Create a `.env` file:

```env
DB_HOST=127.0.0.1
DB_USER=your_mysql_user
DB_PASSWORD=your_mysql_password
DB_NAME=your_database_name
PORT=3001
```

Start the backend:

```bash
npm run dev      # development (nodemon)
npm start        # production
```

### 3. Frontend

```bash
cd fyp-frontend
npm install
```

Create a `.env` file:

```env
VITE_API_BASE_URL=http://localhost:3001
```

Start the frontend:

```bash
npm run dev
```

The dashboard will be available at `http://localhost:5173`.

---

## Running on a Kali VM

If you're running the backend on a Kali Linux VM (e.g. UTM on Mac):

1. Ensure MySQL on the host allows remote connections (`bind-address = 0.0.0.0`)
2. Grant the DB user access from the VM IP:
   ```sql
   GRANT ALL PRIVILEGES ON your_db.* TO 'user'@'192.168.64.2' IDENTIFIED BY 'password';
   ```
3. Update the backend `.env` with `DB_HOST=<host-machine-ip>`
4. Use `sync.sh` to push code changes from Mac to the VM:
   ```bash
   chmod +x sync.sh
   ./sync.sh
   ```

---

## API Endpoints

| Method | Endpoint                  | Description                    |
|--------|---------------------------|--------------------------------|
| GET    | `/api/alerts`             | Fetch all alerts               |
| POST   | `/api/alerts`             | Create an alert                |
| DELETE | `/api/alerts/:id`         | Delete a single alert          |
| DELETE | `/api/alerts`             | Delete all alerts              |
| GET    | `/api/vulnerabilities`    | Fetch all vulnerabilities      |
| DELETE | `/api/vulnerabilities/:id`| Delete a single vulnerability  |
| POST   | `/api/tools/run`          | Run Nmap, Metasploit, Nikto, Lynis, Hydra, or SQLMap scan |
| GET    | `/api/ai`                 | AI endpoint health check       |
| POST   | `/api/ai/analyze-pcap`    | Analyse a PCAP file with ML    |
