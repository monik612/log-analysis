# Log Analyzer — Full-Stack App

## Structure

```
app/
├── backend.py        ← Flask server (API + serves frontend)
└── static/
    └── index.html    ← Dashboard UI
```

## Run

```bash
# 1. Install Flask (if not already installed)
pip install flask

# 2. Start the server
python backend.py

# 3. Open in your browser
http://localhost:5000
```

## API Endpoints

| Method | Endpoint               | Description                     |
|--------|------------------------|---------------------------------|
| GET    | `/api/analyze/sample`  | Analyze built-in sample log     |
| POST   | `/api/analyze/upload`  | Upload a log file (multipart)   |
| POST   | `/api/analyze/text`    | Send raw log text as JSON       |
| GET    | `/`                    | Serves the dashboard            |

### POST /api/analyze/text
```json
{ "text": "Jan 10 08:12:01 server sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2" }
```

## Features
- Detects brute-force login attempts (≥5 failures from same IP)
- Flags all external/unusual IPs
- Severity levels: CRITICAL (8+), HIGH (5+), MEDIUM
- Filterable log table (All / Failed / Success / External IPs)
- File upload or paste-in log text
- Sample data built-in for demo
