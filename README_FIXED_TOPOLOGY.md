# Aegis Zero-Trust — Stable V8

This release keeps the V8 backend/API/policy/segmentation/audit functionality and fixes the dashboard topology renderer.

## Topology behavior

- Deterministic radial/spoke placement is used for live and simulated graphs.
- A deterministic high-degree node is selected as the visual center when connections exist.
- Nodes are pinned during refreshes, so the graph does not turn into a force-directed hairball every few seconds.
- Labels are shown for small graphs and for risky/central nodes on larger graphs.
- Zoom, node drag, node details, risk highlighting, and refresh remain available.

## Demo

Run `RUN_DEMO.bat`.

It regenerates the simulated snapshot, starts the backend on port 5000, starts the dashboard on port 8000, and opens the browser.

## Live

Run `RUN_LIVE.bat`.

This starts the existing psutil-based live capture pipeline. On Windows, some process/network attribution may be permission-limited; that is reported by the dashboard rather than treated as a crash.

## Manual

Terminal 1:

```text
cd "Scan input"
python backend_server.py --mode simulated
```

Terminal 2:

```text
python -m http.server 8000
```

Then open `http://127.0.0.1:8000/dashboard.html`.
