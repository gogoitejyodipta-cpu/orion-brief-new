# ORION Brief v2 — Python Server

## Features
- **Login & accounts** — secure auth, SQLite database
- **8 client profiles** — Maritime, Security, Finance, Cyber, Defence, Government, Aviation, Media
- **Profile-differentiated briefs** — each profile gets a different Claude-generated brief tuned to their sector
- **Email delivery** — morning brief sent to each user's inbox at 06:00 IST
- **Custom alert rules** — watch for any keyword, location, or threat score threshold

## Setup (2 minutes)

```bash
# 1. Install
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Edit .env:
#   ANTHROPIC_API_KEY = your key from console.anthropic.com
#   SMTP_USER / SMTP_PASS = Gmail address + App Password (for email delivery)

# 3. Run
python app.py

# 4. Open
# http://localhost:5000
# → Click "Create account" → pick your profile → dashboard loads
```

## Email Setup (Gmail)
1. Go to myaccount.google.com/apppasswords
2. Generate a 16-character App Password
3. Add to .env:  SMTP_USER=you@gmail.com  SMTP_PASS=xxxx-xxxx-xxxx-xxxx
4. Users who enable "Email Digest" in Settings get the brief in their inbox at 06:00 IST

## Deploy to Railway
```bash
npm install -g @railway/cli
railway login
railway init
railway up
```
Add these in Railway dashboard → Variables:
- ANTHROPIC_API_KEY
- SECRET_KEY  (any random 32-char string)
- SMTP_USER / SMTP_PASS  (for email)

## Alert Rules
Users can create rules like:
- "Place contains Pakistan" → fires when a Pakistan event hits the feed
- "Score ≥ 75" → fires on any CRITICAL event
- "Title contains ransomware" → cyber team gets notified immediately
- Email sent automatically when a rule triggers (if SMTP configured)

## Files
- app.py — Flask server, all logic
- templates/login.html — login page
- templates/register.html — account creation with profile picker
- templates/index.html — main dashboard
- orion.db — SQLite database (auto-created on first run)
- brief_cache.json — cached briefs survive restarts
