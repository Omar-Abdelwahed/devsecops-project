# DevSecOps training app (intentionally vulnerable)

Run locally (Python 3.8-3.10 recommended):
    python -m venv venv && source venv/bin/activate
    pip install -r requirements.txt
    python -m pytest tests/ -v
    python app/app.py            # http://localhost:5000

Or with Docker:
    docker build -t devsecops-app . && docker run -p 5000:5000 devsecops-app

Planted flaws: hardcoded secrets, SQLi, XSS (stored + reflected), SSTI, command injection,
weak MD5 hashing, debug mode, outdated dependencies, outdated root Docker image.
