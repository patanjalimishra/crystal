# Crystal Candidate Screener

## Run locally
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000 and create your own account. No shared/default credentials.

## Deploy (Render)
1. Push this folder to a GitHub repository.
2. Create a Render **Web Service** from the repository.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`
5. Add environment variable `SECRET_KEY` with a long random value.
6. Attach a persistent disk and set `DATABASE_PATH` to a file on that disk, e.g. `/var/data/screener.db`. Mount the disk at `/var/data`.
7. Open the deployed URL and create an account.

SQLite is suitable for a small demo; use managed PostgreSQL and migrations for production. Set secure cookie flags and HTTPS enforcement for production.

## What it does
- Account registration/login with salted password hashing and per-user role ownership.
- Role setup and must-have requirements.
- Candidate intake through pasted resume text.
- Pre-scoring integrity checks: possible prompt injection, date conflicts/overlaps, repeated percentage-based achievement templates.
- Transparent keyword-based fit score with matched/missing requirements.
- Candidate comparison with evidence-linked requirement matches.
- Flags never automatically reject a candidate. They are prompts for human review.

## Important limitations
- Date parsing handles common English month/year and year-only ranges, not every resume format.
- The template check is heuristic and can flag legitimate repeated writing styles.
- Keyword matching is not semantic and is not a hiring recommendation.
- Prompt-injection detection uses patterns; obfuscated or novel attacks may pass.
- This prototype stores plain-text resumes in SQLite. Restrict access, use HTTPS, backups, retention/deletion controls, and appropriate privacy notices before real use.
