# Zero-Trust Dashboard

This project is a live network-monitoring dashboard. The backend reads active
network connections from the local Windows machine, runs risk rules, and
serves the results to `dashboard.html`.

## Requirements

- Windows with Python installed
- The included workspace virtual environment
- Administrator PowerShell for full network visibility

The application only reads network connection metadata. It does not read
personal files or change firewall rules automatically.

## Install dependencies

Open PowerShell in the `zerotrust_project` folder and run:

```powershell
& "..\.venv\Scripts\python.exe" -m pip install flask flask-cors psutil
```

If that relative path does not work, use the full workspace path:

```powershell
& "C:\Users\Dell\OneDrive\Documents\projects\zerotrust_project_updated\.venv\Scripts\python.exe" -m pip install flask flask-cors psutil
```

## Start the live backend

Open **Administrator PowerShell** and run this single command:

```powershell
& "C:\Users\Dell\OneDrive\Documents\projects\zerotrust_project_updated\.venv\Scripts\python.exe" "C:\Users\Dell\OneDrive\Documents\projects\zerotrust_project_updated\zerotrust_project\Scan input\backend_server.py"
```

Keep this window open. A successful start shows:

```text
[*] Mode: LIVE
* Running on http://127.0.0.1:5000
```

The backend captures active connections every two seconds. Press `Ctrl+C` to
stop it.

## Start the dashboard

In a second PowerShell window, from the `zerotrust_project` folder, run:

```powershell
& "..\.venv\Scripts\python.exe" -m http.server 8000
```

Open:

```text
http://127.0.0.1:8000/dashboard.html
```

Use `Ctrl+F5` after changing frontend files.

## Understanding the dashboard

- **Total devices** means unique network endpoints seen recently. Internet
	servers count as endpoints; they are not necessarily physical devices.
- **Connections** is the recent rolling connection window.
- **Risk alerts** are detections produced by the live risk engine.
- **Policies generated** are suggested firewall rules only. They are not
	applied automatically.
- A risk count of zero is a valid healthy live state.

The live detector suppresses ordinary loopback application traffic and uses a
fan-out threshold of 20 new destinations to reduce false positives from normal
browsers, VS Code, and background services.

## Safe presentation demo

For a presentation, first show the normal live state with zero alerts. Then
explain that the following is a controlled scan against your own machine.

Temporarily remove the loopback-scan exclusion in
`Scan input/risk_engine.py`, restart the backend, and run this in another
PowerShell window:

```powershell
cd "C:\Users\Dell\OneDrive\Documents\projects\zerotrust_project_updated\zerotrust_project\Scan input"
& "C:\Users\Dell\OneDrive\Documents\projects\zerotrust_project_updated\.venv\Scripts\python.exe" port_scan_simulator.py
```

The dashboard should show a `PORT_SCANNING` alert and a suggested policy.
Restore the exclusion after the presentation and restart the backend.

## Rebuild Tailwind CSS

You only need this after adding new Tailwind classes to `dashboard.html`.
Node.js is required:

```bash
npx tailwindcss@3 -i input.css -o tailwind.css --content "./dashboard.html" --minify
```

`input.css` should contain:

```css
@tailwind base;
@tailwind utilities;
```

There is no framework or bundler. The dashboard uses the generated static
`tailwind.css` file directly.


## Policy approval workflow

Generated policies are read-only recommendations until a human reviewer makes a decision in the dashboard. Each policy can be **Approved** or **Rejected**. The decision is persisted in SQLite and survives live capture cycles; it does **not** execute firewall commands. The backend exposes `POST /api/policies/<policy_id>/decision` and `GET /api/policy-decisions`.
<<<<<<< HEAD

## Real AI Security Analyst

The AI Security Analyst is a real optional LLM layer, not a fake/random AI label. The deterministic risk engine remains authoritative; the LLM receives a compact security summary and returns an analyst assessment, why-it-matters explanation, evidence points, and recommended next steps. It never executes firewall changes.

To enable real AI on Windows PowerShell, set your API key in the backend terminal before starting Flask:

```powershell
$env:OPENAI_API_KEY="YOUR_API_KEY"
$env:OPENAI_MODEL="gpt-5.6-luna"
python backend_server.py --mode simulated --port 5000
```

If `OPENAI_API_KEY` is absent or the API call fails, the UI explicitly labels the result as a deterministic fallback instead of pretending that a model was used.
=======
>>>>>>> aedc1db9c0a785e87c7499f58808919e6eb2e90c
