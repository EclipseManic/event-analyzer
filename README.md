# Event-Analyzer

Event-Analyzer is a fast, analyst-first Windows EVTX viewer. It focuses on the core Event Viewer workflows: upload, filter, search, sort, and export.

## Features
- Upload one or many .evtx files
- Fast search and filtering
- Sort by time (asc or desc)
- Export filtered results to CSV or JSON
- Simple investigation list and progress view

## Quick start

```powershell
# 1) Install dependencies
pip install -r requirements.txt

# 2) Optional: copy and edit config
copy settings\.env.example settings\.env

# 3) Run the server
python run.py
```

Open http://127.0.0.1:5050

## Notes
- The Rust-based EVTX parser (`evtx`, already in requirements) is required for this viewer.
