# VerifLink

VerifLink is a lightweight phishing detection web app that evaluates **URLs** and **messages** (SMS/email) for suspicious characteristics. It uses a **risk score** plus heuristic-based checks to classify inputs as **Safe**, **Suspicious**, or **Dangerous**.

---

## What it includes

### Frontend (UI)
- Location: `frontend/`
- Files:
  - `frontend/index.html` – Single-page UI with two tabs:
    - **URL Scanner** (paste a URL)
    - **Message Scanner** (paste message + sender)
  - `frontend/app.js` – Handles UI events and communicates with the backend.
  - `frontend/styles.css` – Styling and theme support.

**What the frontend does**
- Lets the user switch between URL and Message scanning.
- Validates inputs (e.g., URL must look like a domain / hostname).
- Sends requests to the backend:
  - `POST /analyze` for URLs
  - `POST /analyze-message` for messages
- Displays the returned result:
  - Status label: Safe / Suspicious / Dangerous
  - Numeric risk score (0–100)
  - Reasons/details returned by the backend

### Backend (API)
- Location: `backend/`
- File:
  - `backend/app.py` – Flask server exposing API endpoints.

**What the backend does**
- Provides HTTP endpoints for scanning and returns JSON responses to the frontend.
- Enables CORS so the frontend can call the API from the browser.

API endpoints:
- `GET /health`
  - Returns: `{ "status": "ok", "version": "1.0.0" }`
- `POST /analyze`
  - Body: `{ "url": "https://example.com" }`
  - Returns the analysis produced by the URL analyzer (`backend/analyzer.py`).
- `POST /analyze-message`
  - Body: `{ "sender": "...", "message": "..." }`
  - Returns the analysis produced by the message analyzer (`backend/messagesScan.py`).

---

## Risk scoring / classification (high level)
The backend returns a JSON structure that typically includes:
- `status` (e.g., safe/suspicious/dangerous)
- `score` (0–100)
- `reasons` (list of detected indicators)
- additional fields depending on the analyzer implementation

The frontend formats these values into the UI.

---

## How to run

### 1) Start the backend
From the project root (`VerifLink/`):
- Run the Flask app (entry: `backend/app.py`).
- The API expects to listen on `http://127.0.0.1:5000`.

### 2) Open the frontend
- Open `frontend/index.html` in a browser.

The frontend will call the backend at `http://127.0.0.1:5000/...`.

---

## Folder overview
- `backend/` – Flask API + analyzers
- `frontend/` – UI + client-side logic

---

## For missing packages
```console
$ pip install -r requirements.txt
```

---

## Notes
- This project is intended for **educational and security research use**.
- Always treat results as **assistance**, not absolute guarantees.
