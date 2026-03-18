"""
ORION Brief — Python Flask Backend v6
========================================
NEW in v6 — Forgot Password (PR):
  PR-01   password_reset_tokens table — token, user_id, expires_at (1h), used flag
  PR-02   create_reset_token() — secrets.token_urlsafe(32), stored hashed, 1h TTL
  PR-03   get_valid_reset_token() — validates token hash, expiry, and used flag
  PR-04   consume_reset_token() — marks used + invalidates all other tokens for user
  PR-05   update_password() — replaces password_hash, logs reset timestamp
  PR-06   send_password_reset_email() — ORION-branded HTML email with reset link
  PR-07   GET/POST /forgot-password — email input, never reveals if email exists
  PR-08   GET/POST /reset-password/<token> — new password form, validates token first
  PR-09   forgot_password.html + reset_password.html templates
  PR-10   "Forgot password?" link added to login.html

NEW in v6 — Custom Watchlist (WL):
  WL-01   watchlist column in users table — comma/newline separated asset terms, max 20 items
  WL-01   update_user_settings() normalises and stores watchlist (trim, dedup, 60-char limit)
  WL-01   api_settings POST now reads, saves, and returns normalised watchlist items
  WL-02   parse_watchlist() — raw string → clean list, dedup, max 60 chars per item
  WL-02   _watchlist_section() — builds prompt injection block for brief generator
  WL-02   generate_brief_for_profile() boosts watchlist-matching events +25pts into top_ev
  WL-02   Brief prompt instructs Claude to name at least 2-3 watchlist items with status
  WL-02   ask_orion() now accepts watchlist_items — boosts matching events to top of NLQ context
  WL-03   api_brief injects user watchlist per-request — watchlist users never see generic cache
  WL-03   api_ask injects user watchlist into every NLQ call
  WL-03   send_morning_digests() already per-user with watchlist since v5 (unchanged)
  WL-UI   Settings panel: watchlist textarea with live preview, tag strip after save
  WL-UI   Brief header: green "◈ WATCHLIST ×N ACTIVE" badge when watchlist is in use

v5 (carried forward):
  PAY-01..03  Razorpay one-time orders, subscriptions table, paywall
  ADM-01..03  Admin panel, ADMIN_EMAIL guard, API endpoints
  DQ-01..05   GDELT noise filter, dedup, domain scoring, threshold, confidence
  SSL-01      BASE_URL for custom domain email links

NEW in v5:
  REC-01   Razorpay Subscriptions API — auto-recurring monthly billing, no manual chase
  REC-02   Razorpay webhook endpoint — /api/payment/webhook handles charged/cancelled events
  REC-03   DB: razorpay_sub_id + billing_cycle on subscriptions, invoices table
  REC-04   Subscription webhook signature verified via HMAC on raw body
  INV-01   GST invoice generation — invoices table, unique invoice numbers (ORN-YYYY-NNNN)
  INV-02   /invoice/<inv_id> route — branded HTML invoice, browser-print to PDF
  INV-03   Admin and client can access own invoices; admin sees all
  INV-04   18% GST breakdown (CGST 9% + SGST 9%), totals in rupees
  DATA-01  ACLED API fetcher — verified conflict data for South Asia (PAK, IND, AFG, MMR)
  DATA-02  NewsAPI fetcher — English news feed with same DQ scoring pipeline as GDELT
  DATA-03  Both fetchers gated behind env vars; fallback gracefully if keys absent
  DATA-04  load_all_data() now pulls from 6 sources: USGS, GDELT, CISA, ReliefWeb, ACLED, NewsAPI
"""

import os, json, time, atexit, random, threading, smtplib, hashlib, secrets, hmac
from datetime import datetime, timezone, timedelta
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import sqlite3
import requests
from flask import (Flask, render_template, jsonify, request,
                   session, redirect, url_for)
from anthropic import Anthropic
from apscheduler.schedulers.background import BackgroundScheduler
from functools import wraps

try:
    from dotenv import load_dotenv; load_dotenv()
except ImportError:
    pass

# ── ENV ──────────────────────────────────────────────────────────────
ANTHROPIC_KEY   = os.environ.get("ANTHROPIC_API_KEY", "")
PORT            = int(os.environ.get("PORT", 5000))
SECRET_KEY      = os.environ.get("SECRET_KEY", secrets.token_hex(32))
SMTP_SERVER     = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT_ENV   = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER       = os.environ.get("SMTP_USER", "")
SMTP_PASS       = os.environ.get("SMTP_PASS", "")
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID", "")
RAZORPAY_SECRET = os.environ.get("RAZORPAY_SECRET", "")
ADMIN_EMAIL     = os.environ.get("ADMIN_EMAIL", "").lower()
BASE_URL        = os.environ.get("BASE_URL", f"http://localhost:{PORT}")
# DATA-01 + DATA-02: new feed keys — platform works without these, just fewer sources
ACLED_API_KEY   = os.environ.get("ACLED_API_KEY", "")
ACLED_EMAIL     = os.environ.get("ACLED_EMAIL", "")
NEWSAPI_KEY     = os.environ.get("NEWSAPI_KEY", "")
# INV: GST registration details for invoices
GST_NUMBER      = os.environ.get("GST_NUMBER", "")          # your GSTIN once registered
BUSINESS_NAME   = os.environ.get("BUSINESS_NAME", "ORION Intelligence Technologies")
BUSINESS_ADDR   = os.environ.get("BUSINESS_ADDR", "Guwahati, Assam, India")
IST             = timezone(timedelta(hours=5, minutes=30))
DB_PATH         = Path(__file__).parent / "orion.db"
CACHE_FILE      = Path(__file__).parent / "brief_cache.json"

app                             = Flask(__name__)
app.secret_key                  = SECRET_KEY
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=24)
app.config["SESSION_COOKIE_HTTPONLY"]    = True
app.config["SESSION_COOKIE_SAMESITE"]    = "Lax"

client = Anthropic(api_key=ANTHROPIC_KEY) if ANTHROPIC_KEY else None

cache = {
    "events": [], "threat_score": 0, "brief_level": "NOMINAL",
    "last_fetch": None, "next_refresh": "",
    "briefs": {},
}

# ── PLANS ─────────────────────────────────────────────────────────────
PLANS = {
    "brief": {
        "name":        "ORION Brief",
        "price_inr":   15000,
        "price_paise": 1500000,
        "features":    ["Morning intelligence brief", "Live alert strip (top 5)", "Ask Anything NLQ", "8 client profiles", "Email digest at 06:00 IST", "Custom alert rules"],
        "color":       "#3b82f6",
        "popular":     False,
    },
    "standard": {
        "name":        "ORION Standard",
        "price_inr":   40000,
        "price_paise": 4000000,
        "features":    ["Everything in Brief", "Full interactive map", "Naval & Air tabs", "Chokepoint deep-dive", "Multi-recipient email", "Priority support"],
        "color":       "#f59e0b",
        "popular":     True,
    },
    "full": {
        "name":        "ORION Full",
        "price_inr":   100000,
        "price_paise": 10000000,
        "features":    ["Everything in Standard", "Complete v12 dashboard", "White-label option", "Custom watchlist", "API access", "Dedicated onboarding"],
        "color":       "#ef4444",
        "popular":     False,
    },
}

# ─────────────────────────────────────────────────────────────────────
# CLIENT PROFILES
# ─────────────────────────────────────────────────────────────────────
PROFILES = {
    "maritime": {
        "label":"Maritime & Shipping","icon":"⚓","color":"#0891b2",
        "focus":["hormuz","red sea","malacca","aden","ior","naval","vessel","ship","port"],
        "topics":["Chokepoint Status","IOR Naval Posture","Vessel Incidents","India Shipping Impact","Cascade Supply Risk"],
        "brief_directive":"Focus on chokepoints (Red Sea, Hormuz, Malacca), IOR naval posture, vessel incidents. Lead every brief with chokepoint status. Include specific freight cost impact estimates.",
        "suggestions":["Red Sea threat level for Indian vessels today","Hormuz closure probability this week","Which Indian ports are most exposed right now","PLAN naval activity near Malacca this week","Current freight cost impact of Red Sea disruption"],
    },
    "security": {
        "label":"Security & Risk Consultancy","icon":"🛡","color":"#dc2626",
        "focus":["pakistan","china","border","loc","lac","conflict","attack","militant"],
        "topics":["LoC/LAC Border Status","Active Conflict Zones","Threat Actor Activity","Travel Risk Assessment","Cascade Security Risk"],
        "brief_directive":"Lead with LoC and LAC border situation. Cover active conflict zones relevant to corporate security and travel risk. Frame through personnel safety for MNCs in South Asia.",
        "suggestions":["Pakistan border situation last 48 hours","Corporate personnel safety in northern India","Active militant activity near India industrial corridors","China LAC escalation risk this week","Which South Asian cities have elevated risk right now"],
    },
    "finance": {
        "label":"Financial Services & Trading","icon":"📈","color":"#f59e0b",
        "focus":["hormuz","oil","brent","rupee","supply","wheat","fertiliser","taiwan","semiconductor"],
        "topics":["Oil Supply Risk","Cascade Economic Impact","Chokepoint Cost Analysis","India Macro Impact","Market-Moving Events"],
        "brief_directive":"Lead with events moving oil, rupee, or Indian equity markets. T3 cascade chains. Include Brent corridor risk, food/fertiliser disruption, semiconductor events. Frame through P&L.",
        "suggestions":["Oil supply risk from Middle East today","How does Red Sea affect India inflation","Taiwan Strait semiconductor supply chain impact","Which cascade events could move Indian equity markets","Russia/Ukraine India fertiliser and wheat exposure"],
    },
    "cyber": {
        "label":"Cyber Security / SOC","icon":"💻","color":"#a855f7",
        "focus":["cyber","ransomware","cisa","vulnerability","malware","phishing","cert"],
        "topics":["Active Exploits (CISA KEV)","Ransomware Campaigns","India CERT-In Alerts","Critical Infrastructure Threats","Hybrid Cyber-Military"],
        "brief_directive":"Lead with CISA KEV active exploits and ransomware campaigns. Focus on India government, BFSI, critical infrastructure. Frame through CERT-In advisory status and patch urgency.",
        "suggestions":["Top active ransomware families targeting India","CISA KEV affecting Indian government software","Cyber activity correlated with Pakistan/China military moves","Critical infrastructure sectors most at risk","Active phishing campaigns targeting Indian financial sector"],
    },
    "defence": {
        "label":"Defence & Think Tank","icon":"⚔️","color":"#ef4444",
        "focus":["military","army","navy","airforce","nuclear","missile","pla","ispr","drdo"],
        "topics":["Border Military Posture","Nuclear Signalling","IOR Military Balance","Hybrid Operation Indicators","Strategic Cascade Assessment"],
        "brief_directive":"Full 4-tier strategic brief. Lead with border military posture (LoC + LAC). Include nuclear signalling. Cover IOR military balance. Flag hybrid operation indicators.",
        "suggestions":["Pakistan nuclear signalling assessment this week","PLA posture at all five LAC friction points","Hybrid operation indicators cyber correlated with military","India strategic deterrence posture assessment","IOR military balance India Navy vs PLAN"],
    },
    "government": {
        "label":"Government & Policy","icon":"🏛","color":"#f97316",
        "focus":["india","policy","diplomatic","ministry","ndma","disaster","refugee","border"],
        "topics":["India Strategic Threat Picture","Diplomatic Pressure Points","Humanitarian & Disaster Risk","District-Level Threats","Policy Recommendations"],
        "brief_directive":"Executive-level brief for MEA, PMO, or NSA advisory. Include humanitarian situations requiring diplomatic engagement. Policy-grade language.",
        "suggestions":["Executive summary of India threat picture this week","Which border situations require diplomatic attention","Humanitarian situations requiring Indian government response","Strategic risks to India neighbourhood first policy","SAARC region instability current assessment"],
    },
    "aviation": {
        "label":"Aviation & Airspace","icon":"✈️","color":"#22d3ee",
        "focus":["aircraft","airspace","squawk","aviation","dgca","notam","pilot","airport"],
        "topics":["Airspace Threat Assessment","Emergency Squawk Activity","Conflict Zone Flight Paths","India DGCA Alerts","Chokepoint Aviation Risk"],
        "brief_directive":"Lead with airspace threats and emergency squawk activity. Cover conflict zones affecting Indian airline routing. Frame for airline ops professionals.",
        "suggestions":["Emergency squawk codes over India or South Asia right now","Conflict zones affecting Indian airline routes","Persian Gulf airspace risk for Indian carriers","Pakistan airspace status for Indian commercial aviation","NOTAM-relevant events in current intelligence picture"],
    },
    "media": {
        "label":"Media & Journalism","icon":"📰","color":"#22c55e",
        "focus":["conflict","attack","crisis","killed","casualties","explosion","protest"],
        "topics":["Breaking Conflict Events","Casualty Reports","Crisis Developments","Regional Stability Index","Story Leads"],
        "brief_directive":"Lead with most newsworthy conflict and crisis events. Focus on verified ACLED and GDELT data with source attribution. Frame as story leads for journalists covering South Asia.",
        "suggestions":["Most significant conflict events last 24 hours with sources","Verified data on Pakistan border incidents this week","What happened near India borders in the last 48 hours","Crisis situations with highest media significance","Which South Asian stories are underreported this week"],
    },
}

# ─────────────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            email          TEXT UNIQUE NOT NULL,
            password_hash  TEXT NOT NULL,
            name           TEXT NOT NULL,
            profile        TEXT NOT NULL DEFAULT 'maritime',
            email_digest   INTEGER NOT NULL DEFAULT 1,
            digest_time    TEXT NOT NULL DEFAULT '06:00',
            created_at     TEXT NOT NULL,
            last_login     TEXT,
            last_active    TEXT,
            watchlist      TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS subscriptions (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id             INTEGER UNIQUE NOT NULL,
            plan                TEXT NOT NULL DEFAULT 'brief',
            status              TEXT NOT NULL DEFAULT 'active',
            amount_paise        INTEGER NOT NULL DEFAULT 0,
            razorpay_order_id   TEXT,
            razorpay_payment_id TEXT,
            razorpay_sub_id     TEXT,
            billing_cycle       TEXT NOT NULL DEFAULT 'one_time',
            started_at          TEXT NOT NULL,
            expires_at          TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        -- INV-01: invoice ledger — one row per billing event
        CREATE TABLE IF NOT EXISTS invoices (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_number  TEXT UNIQUE NOT NULL,
            user_id         INTEGER NOT NULL,
            plan            TEXT NOT NULL,
            amount_paise    INTEGER NOT NULL,
            gst_paise       INTEGER NOT NULL,
            total_paise     INTEGER NOT NULL,
            payment_id      TEXT,
            razorpay_sub_id TEXT,
            billing_period  TEXT NOT NULL,
            issued_at       TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS alert_rules (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id        INTEGER NOT NULL,
            name           TEXT NOT NULL,
            field          TEXT NOT NULL,
            operator       TEXT NOT NULL,
            value          TEXT NOT NULL,
            active         INTEGER NOT NULL DEFAULT 1,
            last_triggered TEXT,
            trigger_count  INTEGER NOT NULL DEFAULT 0,
            created_at     TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS alert_log (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            rule_id      INTEGER NOT NULL,
            event_title  TEXT NOT NULL,
            event_place  TEXT,
            triggered_at TEXT NOT NULL,
            email_sent   INTEGER NOT NULL DEFAULT 0,
            email_error  TEXT
        );

        CREATE TABLE IF NOT EXISTS email_delivery_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            email_type  TEXT NOT NULL,
            subject     TEXT NOT NULL,
            sent_at     TEXT NOT NULL,
            delivered   INTEGER NOT NULL DEFAULT 0,
            error_msg   TEXT,
            retry_count INTEGER NOT NULL DEFAULT 0
        );

        -- PR-01: password reset tokens — one-use, 1-hour TTL
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            token_hash  TEXT NOT NULL UNIQUE,
            created_at  TEXT NOT NULL,
            expires_at  TEXT NOT NULL,
            used        INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)
        # safe column additions for schema upgrades
        for col_sql in [
            "ALTER TABLE users ADD COLUMN last_active TEXT",
            "ALTER TABLE users ADD COLUMN watchlist TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE subscriptions ADD COLUMN razorpay_sub_id TEXT",
            "ALTER TABLE subscriptions ADD COLUMN billing_cycle TEXT NOT NULL DEFAULT 'one_time'",
        ]:
            try: db.execute(col_sql); db.commit()
            except: pass
    print("✓ Database initialised (v4)")


def hash_password(p): return hashlib.sha256((p + SECRET_KEY).encode()).hexdigest()

def create_user(email, password, name, profile):
    try:
        now = datetime.now(IST).isoformat()
        with get_db() as db:
            db.execute("INSERT INTO users (email,password_hash,name,profile,created_at,last_active) VALUES (?,?,?,?,?,?)",
                       (email.lower(), hash_password(password), name, profile, now, now))
            db.commit()
        return True, None
    except sqlite3.IntegrityError: return False, "Email already registered"
    except Exception as e: return False, str(e)

def get_user_by_email(email):
    with get_db() as db: return db.execute("SELECT * FROM users WHERE email=?", (email.lower(),)).fetchone()

def get_user_by_id(uid):
    with get_db() as db: return db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def update_last_login(uid):
    now = datetime.now(IST).isoformat()
    with get_db() as db:
        db.execute("UPDATE users SET last_login=?,last_active=? WHERE id=?", (now, now, uid)); db.commit()

def update_last_active(uid):
    with get_db() as db:
        db.execute("UPDATE users SET last_active=? WHERE id=?", (datetime.now(IST).isoformat(), uid)); db.commit()


# ── PASSWORD RESET — PR-02 .. PR-05 ─────────────────────────────────

def _hash_token(raw_token: str) -> str:
    """Store only the SHA-256 hash of the token — raw token lives only in the email link."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


def create_reset_token(user_id: int) -> str:
    """PR-02: Generate a secure URL-safe token, store its hash, return raw token for the email link."""
    raw   = secrets.token_urlsafe(32)           # 256 bits of entropy
    thash = _hash_token(raw)
    now   = datetime.now(IST)
    exp   = (now + timedelta(hours=1)).isoformat()
    with get_db() as db:
        # Invalidate any existing unused tokens for this user first
        db.execute("UPDATE password_reset_tokens SET used=1 WHERE user_id=? AND used=0", (user_id,))
        db.execute(
            "INSERT INTO password_reset_tokens (user_id,token_hash,created_at,expires_at,used) VALUES (?,?,?,?,0)",
            (user_id, thash, now.isoformat(), exp)
        )
        db.commit()
    return raw


def get_valid_reset_token(raw_token: str):
    """PR-03: Return token row if valid, not expired, not used. None otherwise."""
    thash = _hash_token(raw_token)
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM password_reset_tokens WHERE token_hash=? AND used=0", (thash,)
        ).fetchone()
    if not row:
        return None
    try:
        exp = datetime.fromisoformat(row["expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=IST)
        if datetime.now(IST) > exp:
            return None          # expired
    except Exception:
        return None
    return row


def consume_reset_token(token_id: int, user_id: int):
    """PR-04: Mark this token used AND invalidate all other tokens for the same user."""
    with get_db() as db:
        db.execute("UPDATE password_reset_tokens SET used=1 WHERE user_id=?", (user_id,))
        db.commit()


def update_password(user_id: int, new_password: str):
    """PR-05: Replace password hash and record reset timestamp."""
    new_hash = hash_password(new_password)
    now      = datetime.now(IST).isoformat()
    with get_db() as db:
        db.execute(
            "UPDATE users SET password_hash=?, last_active=? WHERE id=?",
            (new_hash, now, user_id)
        )
        db.commit()

def update_user_settings(uid, name, profile, email_digest, digest_time, watchlist=""):
    """WL-01: persist watchlist alongside other settings."""
    # Normalise watchlist — strip whitespace, deduplicate, max 20 items, max 60 chars each
    items = [w.strip() for w in watchlist.replace(",", "\n").splitlines() if w.strip()]
    items = list(dict.fromkeys(items))[:20]                  # dedup, keep order, cap at 20
    items = [i[:60] for i in items]                          # cap each item length
    clean_watchlist = "\n".join(items)
    with get_db() as db:
        db.execute(
            "UPDATE users SET name=?,profile=?,email_digest=?,digest_time=?,watchlist=?,last_active=? WHERE id=?",
            (name, profile, int(email_digest), digest_time,
             clean_watchlist, datetime.now(IST).isoformat(), uid)
        )
        db.commit()


# ── SUBSCRIPTIONS ─────────────────────────────────────────────────────

def get_subscription(user_id):
    with get_db() as db:
        return db.execute("SELECT * FROM subscriptions WHERE user_id=?", (user_id,)).fetchone()

def create_subscription(user_id, plan, amount_paise, razorpay_order_id, razorpay_payment_id,
                         razorpay_sub_id=None, billing_cycle="one_time"):
    now     = datetime.now(IST)
    # Recurring: extend 31 days from now on each charge; one_time: 31 days from start
    expires = (now + timedelta(days=31)).isoformat()
    cycle   = "recurring" if razorpay_sub_id else billing_cycle
    with get_db() as db:
        db.execute("""INSERT INTO subscriptions
            (user_id,plan,status,amount_paise,razorpay_order_id,razorpay_payment_id,
             razorpay_sub_id,billing_cycle,started_at,expires_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(user_id) DO UPDATE SET
              plan=excluded.plan, status='active', amount_paise=excluded.amount_paise,
              razorpay_order_id=excluded.razorpay_order_id,
              razorpay_payment_id=excluded.razorpay_payment_id,
              razorpay_sub_id=COALESCE(excluded.razorpay_sub_id, subscriptions.razorpay_sub_id),
              billing_cycle=excluded.billing_cycle,
              started_at=excluded.started_at, expires_at=excluded.expires_at""",
            (user_id, plan, "active", amount_paise,
             razorpay_order_id, razorpay_payment_id,
             razorpay_sub_id, cycle, now.isoformat(), expires))
        db.commit()

def is_subscription_active(user_id):
    """Admin bypass + actual check."""
    user = get_user_by_id(user_id)
    if user and user["email"].lower() == ADMIN_EMAIL: return True
    sub = get_subscription(user_id)
    if not sub or sub["status"] != "active": return False
    try:
        exp = datetime.fromisoformat(sub["expires_at"])
        if exp.tzinfo is None: exp = exp.replace(tzinfo=IST)
        return datetime.now(IST) < exp
    except: return False

def get_all_subscriptions():
    with get_db() as db:
        return db.execute(
            "SELECT s.*, u.email, u.name, u.profile, u.last_active FROM subscriptions s "
            "JOIN users u ON s.user_id=u.id ORDER BY s.started_at DESC"
        ).fetchall()

def get_all_users_for_admin():
    with get_db() as db:
        return db.execute(
            "SELECT u.*, s.plan, s.status as sub_status, s.expires_at, s.amount_paise, "
            "s.billing_cycle, s.razorpay_sub_id "
            "FROM users u LEFT JOIN subscriptions s ON u.id=s.user_id "
            "ORDER BY u.created_at DESC"
        ).fetchall()


# ── INVOICES — INV-01 ────────────────────────────────────────────────

def _next_invoice_number():
    """Generate sequential invoice number: ORN-2025-0001."""
    year = datetime.now(IST).year
    with get_db() as db:
        row = db.execute(
            "SELECT COUNT(*) as c FROM invoices WHERE invoice_number LIKE ?",
            (f"ORN-{year}-%",)
        ).fetchone()
        seq = (row["c"] if row else 0) + 1
    return f"ORN-{year}-{seq:04d}"


def create_invoice(user_id, plan, amount_paise, payment_id=None, razorpay_sub_id=None):
    """INV-01: Create invoice row. GST = 18% of base amount."""
    gst_paise   = int(amount_paise * 0.18)
    total_paise = amount_paise + gst_paise
    now         = datetime.now(IST)
    period      = now.strftime("%B %Y")
    inv_num     = _next_invoice_number()
    with get_db() as db:
        db.execute(
            "INSERT INTO invoices (invoice_number,user_id,plan,amount_paise,gst_paise,"
            "total_paise,payment_id,razorpay_sub_id,billing_period,issued_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (inv_num, user_id, plan, amount_paise, gst_paise,
             total_paise, payment_id, razorpay_sub_id, period, now.isoformat())
        )
        db.commit()
    return inv_num


def get_user_invoices(user_id, limit=12):
    with get_db() as db:
        return db.execute(
            "SELECT i.*, u.name, u.email FROM invoices i JOIN users u ON i.user_id=u.id "
            "WHERE i.user_id=? ORDER BY i.issued_at DESC LIMIT ?", (user_id, limit)
        ).fetchall()


def get_invoice_by_number(inv_num):
    with get_db() as db:
        return db.execute(
            "SELECT i.*, u.name, u.email FROM invoices i JOIN users u ON i.user_id=u.id "
            "WHERE i.invoice_number=?", (inv_num,)
        ).fetchone()


def get_all_invoices_admin(limit=50):
    with get_db() as db:
        return db.execute(
            "SELECT i.*, u.name, u.email FROM invoices i JOIN users u ON i.user_id=u.id "
            "ORDER BY i.issued_at DESC LIMIT ?", (limit,)
        ).fetchall()


# ── ALERT RULES ──────────────────────────────────────────────────────

def get_user_rules(uid):
    with get_db() as db:
        return db.execute("SELECT * FROM alert_rules WHERE user_id=? ORDER BY created_at DESC", (uid,)).fetchall()

def create_rule(uid, name, field, operator, value):
    with get_db() as db:
        db.execute("INSERT INTO alert_rules (user_id,name,field,operator,value,created_at) VALUES (?,?,?,?,?,?)",
                   (uid, name, field, operator, value, datetime.now(IST).isoformat())); db.commit()

def toggle_rule(rule_id, uid):
    with get_db() as db:
        db.execute("UPDATE alert_rules SET active=1-active WHERE id=? AND user_id=?", (rule_id, uid)); db.commit()

def delete_rule(rule_id, uid):
    with get_db() as db:
        db.execute("DELETE FROM alert_rules WHERE id=? AND user_id=?", (rule_id, uid)); db.commit()

def get_all_active_rules():
    with get_db() as db:
        return db.execute("SELECT r.*, u.email, u.name FROM alert_rules r JOIN users u ON r.user_id=u.id WHERE r.active=1").fetchall()

def mark_rule_triggered(rule_id, event_title, event_place, email_sent, email_error=None):
    now = datetime.now(IST).isoformat()
    with get_db() as db:
        db.execute("UPDATE alert_rules SET last_triggered=?,trigger_count=trigger_count+1 WHERE id=?", (now, rule_id))
        db.execute("INSERT INTO alert_log (user_id,rule_id,event_title,event_place,triggered_at,email_sent,email_error) "
                   "SELECT user_id,?,?,?,?,?,? FROM alert_rules WHERE id=?",
                   (rule_id, event_title, event_place, now, int(email_sent), email_error, rule_id)); db.commit()

def get_user_alert_log(uid, limit=20):
    with get_db() as db:
        return db.execute("SELECT l.*, r.name as rule_name FROM alert_log l JOIN alert_rules r ON l.rule_id=r.id "
                          "WHERE l.user_id=? ORDER BY l.triggered_at DESC LIMIT ?", (uid, limit)).fetchall()

def get_all_alert_log_admin(limit=50):
    with get_db() as db:
        return db.execute("SELECT l.*, r.name as rule_name, u.email, u.name as user_name "
                          "FROM alert_log l JOIN alert_rules r ON l.rule_id=r.id "
                          "JOIN users u ON l.user_id=u.id ORDER BY l.triggered_at DESC LIMIT ?", (limit,)).fetchall()

def log_email_delivery(uid, email_type, subject, delivered, error_msg=None):
    with get_db() as db:
        db.execute("INSERT INTO email_delivery_log (user_id,email_type,subject,sent_at,delivered,error_msg) VALUES (?,?,?,?,?,?)",
                   (uid, email_type, subject, datetime.now(IST).isoformat(), int(delivered), error_msg)); db.commit()

def get_last_digest_status(uid):
    with get_db() as db:
        return db.execute("SELECT * FROM email_delivery_log WHERE user_id=? AND email_type='digest' ORDER BY sent_at DESC LIMIT 1", (uid,)).fetchone()

def get_email_delivery_stats():
    with get_db() as db:
        return db.execute("""SELECT email_type,
            COUNT(*) as total,
            SUM(delivered) as delivered,
            COUNT(*)-SUM(delivered) as failed
            FROM email_delivery_log GROUP BY email_type""").fetchall()

def get_users_with_email_digest():
    with get_db() as db:
        return db.execute("SELECT * FROM users WHERE email_digest=1 AND email IS NOT NULL AND email!=''").fetchall()


# ─────────────────────────────────────────────────────────────────────
# AUTH DECORATORS
# ─────────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json or request.path.startswith("/api/"): return jsonify({"error":"Not authenticated"}), 401
            return redirect(url_for("login_page"))
        update_last_active(session["user_id"])
        return f(*args, **kwargs)
    return decorated


def subscription_required(f):
    """PAY-03: Paywall — redirect to /subscribe if no active subscription."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login_page"))
        uid = session["user_id"]
        update_last_active(uid)
        if not is_subscription_active(uid):
            if request.is_json or request.path.startswith("/api/"): return jsonify({"error":"Subscription required","redirect":"/subscribe"}), 402
            return redirect(url_for("subscribe_page"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """ADM-02: Admin check via ADMIN_EMAIL env var."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login_page"))
        user = get_user_by_id(session["user_id"])
        if not user or user["email"].lower() != ADMIN_EMAIL:
            return jsonify({"error":"Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


def current_user():
    uid = session.get("user_id")
    return get_user_by_id(uid) if uid else None


# ─────────────────────────────────────────────────────────────────────
# RAZORPAY — ONE-TIME ORDERS + SUBSCRIPTIONS API (REC-01..04)
# ─────────────────────────────────────────────────────────────────────

# REC-01: cache of Razorpay plan IDs so we don't recreate them on every subscribe
_rzp_plan_cache: dict = {}


def _rzp_api(method, path, **kwargs):
    """Internal helper for all Razorpay API calls."""
    if not RAZORPAY_KEY_ID or not RAZORPAY_SECRET:
        return None, "Razorpay not configured"
    try:
        r = requests.request(
            method,
            f"https://api.razorpay.com/v1/{path}",
            auth=(RAZORPAY_KEY_ID, RAZORPAY_SECRET),
            timeout=15,
            **kwargs
        )
        r.raise_for_status()
        return r.json(), None
    except requests.HTTPError as e:
        msg = f"Razorpay {path} HTTP {e.response.status_code}: {e.response.text[:200]}"
        print(f"✗ {msg}"); return None, msg
    except Exception as e:
        print(f"✗ Razorpay {path} error: {e}"); return None, str(e)


def razorpay_get_or_create_plan(plan_key):
    """REC-01: Retrieve or create a Razorpay Plan for the given ORION plan key.
    Plans are created once and cached in memory. On restart, re-fetched by ID from env."""
    if plan_key in _rzp_plan_cache:
        return _rzp_plan_cache[plan_key], None
    plan = PLANS.get(plan_key)
    if not plan: return None, "Unknown plan"
    # Check env for a pre-created plan ID (set after first run)
    env_key  = f"RAZORPAY_PLAN_ID_{plan_key.upper()}"
    plan_id  = os.environ.get(env_key)
    if plan_id:
        _rzp_plan_cache[plan_key] = plan_id
        return plan_id, None
    if not RAZORPAY_KEY_ID:
        return f"demo_plan_{plan_key}", None   # demo mode
    # Create new Razorpay plan
    data, err = _rzp_api("POST", "plans", json={
        "period":   "monthly",
        "interval": 1,
        "item": {
            "name":     plan["name"],
            "amount":   plan["price_paise"],
            "currency": "INR",
            "description": f"ORION Brief {plan['name']} — monthly South Asia intelligence subscription",
        }
    })
    if not data: return None, err
    pid = data["id"]
    _rzp_plan_cache[plan_key] = pid
    print(f"✓ Razorpay plan created: {plan_key} = {pid}")
    print(f"  → Add to .env: {env_key}={pid}")
    return pid, None


def razorpay_create_subscription(plan_key, user_email, user_name):
    """REC-01: Create a Razorpay Subscription for auto-recurring monthly billing."""
    if not RAZORPAY_KEY_ID:
        # Demo mode — return fake subscription ID
        return {"id": f"demo_sub_{secrets.token_hex(8)}", "short_url": BASE_URL + "/subscribe"}, None
    plan_id, err = razorpay_get_or_create_plan(plan_key)
    if not plan_id: return None, err
    data, err = _rzp_api("POST", "subscriptions", json={
        "plan_id":             plan_id,
        "total_count":         12,        # 12 months; Razorpay auto-renews if total_count > cycles done
        "quantity":            1,
        "customer_notify":     1,
        "notify_info": {
            "notify_phone": "",
            "notify_email": user_email,
        },
        "notes": {"user_email": user_email, "user_name": user_name, "plan_key": plan_key},
    })
    return data, err


def razorpay_cancel_subscription(sub_id, cancel_at_cycle_end=True):
    """Cancel a Razorpay subscription. cancel_at_cycle_end=True means cancel after current period."""
    data, err = _rzp_api(
        "POST", f"subscriptions/{sub_id}/cancel",
        json={"cancel_at_cycle_end": 1 if cancel_at_cycle_end else 0}
    )
    return data, err


def razorpay_create_order(amount_paise, receipt, notes=None):
    """One-time order (fallback when subscription flow not used)."""
    if not RAZORPAY_KEY_ID or not RAZORPAY_SECRET:
        return {"id": f"demo_order_{secrets.token_hex(8)}", "amount": amount_paise, "currency": "INR"}
    data, err = _rzp_api("POST", "orders", json={
        "amount": amount_paise, "currency": "INR",
        "receipt": receipt, "notes": notes or {}, "payment_capture": 1
    })
    return data


def razorpay_verify_signature(order_id, payment_id, signature):
    """Verify Razorpay payment signature (one-time order flow)."""
    if not RAZORPAY_SECRET: return True  # demo mode
    body     = f"{order_id}|{payment_id}"
    expected = hmac.new(RAZORPAY_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def razorpay_verify_webhook_signature(raw_body: bytes, header_sig: str) -> bool:
    """REC-04: Verify Razorpay webhook signature on raw request body."""
    if not RAZORPAY_SECRET: return True  # demo mode
    expected = hmac.new(RAZORPAY_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header_sig)


def _find_user_by_sub_id(sub_id):
    """Lookup user whose subscription has this Razorpay sub ID."""
    with get_db() as db:
        row = db.execute(
            "SELECT u.* FROM users u JOIN subscriptions s ON u.id=s.user_id WHERE s.razorpay_sub_id=?",
            (sub_id,)
        ).fetchone()
    return row


def handle_webhook_charged(payload):
    """REC-02: subscription.charged — extend expiry 31 days, create invoice."""
    sub_entity  = payload.get("payload", {}).get("subscription", {}).get("entity", {})
    pay_entity  = payload.get("payload", {}).get("payment", {}).get("entity", {})
    sub_id      = sub_entity.get("id")
    payment_id  = pay_entity.get("id")
    amount_paise= pay_entity.get("amount", 0)
    if not sub_id: return
    user = _find_user_by_sub_id(sub_id)
    if not user:
        print(f"⚠ Webhook charged: no user found for sub_id={sub_id}"); return
    sub = get_subscription(user["id"])
    plan_key = sub["plan"] if sub else "brief"
    # Extend subscription 31 days
    create_subscription(user["id"], plan_key, amount_paise,
                        None, payment_id, razorpay_sub_id=sub_id, billing_cycle="recurring")
    # Create invoice row
    inv_num = create_invoice(user["id"], plan_key, amount_paise,
                             payment_id=payment_id, razorpay_sub_id=sub_id)
    # Send renewal email with invoice link
    send_renewal_email(user["email"], user["name"], plan_key, amount_paise // 100, inv_num)
    print(f"✓ Webhook: sub {sub_id} charged — invoice {inv_num} — user {user['email']}")


def handle_webhook_cancelled(payload):
    """REC-02: subscription.cancelled — mark subscription cancelled."""
    sub_entity = payload.get("payload", {}).get("subscription", {}).get("entity", {})
    sub_id     = sub_entity.get("id")
    if not sub_id: return
    with get_db() as db:
        db.execute("UPDATE subscriptions SET status='cancelled' WHERE razorpay_sub_id=?", (sub_id,))
        db.commit()
    print(f"✓ Webhook: sub {sub_id} cancelled")


# ─────────────────────────────────────────────────────────────────────
# EMAIL
# ─────────────────────────────────────────────────────────────────────

def _smtp_send(to_email, msg):
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT_ENV, timeout=15) as srv:
            srv.ehlo(); srv.starttls(); srv.ehlo()
            srv.login(SMTP_USER, SMTP_PASS)
            srv.sendmail(SMTP_USER, to_email, msg.as_string())
        return True, None
    except smtplib.SMTPAuthenticationError: return False, "SMTP auth failed"
    except smtplib.SMTPConnectError:        return False, f"Cannot connect to {SMTP_SERVER}:{SMTP_PORT_ENV}"
    except Exception as e:                  return False, str(e)


def send_email(to_email, subject, body_html, body_text=None, user_id=None, email_type="general"):
    if not SMTP_USER or not SMTP_PASS:
        print(f"⚠  Email skipped (no SMTP): {subject} → {to_email}")
        if user_id: log_email_delivery(user_id, email_type, subject, False, "SMTP not configured")
        return False
    msg             = MIMEMultipart("alternative")
    msg["Subject"]  = subject
    msg["From"]     = f"ORION Brief <{SMTP_USER}>"
    msg["To"]       = to_email
    msg["X-Mailer"] = "ORION-Brief/4.0"
    if body_text: msg.attach(MIMEText(body_text, "plain"))
    msg.attach(MIMEText(body_html, "html"))
    ok, err = _smtp_send(to_email, msg)
    if not ok:
        print(f"⚠  Email failed (attempt 1): {err} — retrying in 10s")
        time.sleep(10); ok, err = _smtp_send(to_email, msg)
    print(f"{'✓' if ok else '✗'} Email {'sent' if ok else 'FAILED'}: {subject} → {to_email}")
    if user_id: log_email_delivery(user_id, email_type, subject, ok, err)
    return ok


def test_smtp_connection():
    if not SMTP_USER or not SMTP_PASS: return False, "SMTP_USER and SMTP_PASS not set in .env"
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT_ENV, timeout=10) as srv:
            srv.ehlo(); srv.starttls(); srv.ehlo(); srv.login(SMTP_USER, SMTP_PASS)
        return True, f"Connected to {SMTP_SERVER}:{SMTP_PORT_ENV} as {SMTP_USER}"
    except smtplib.SMTPAuthenticationError: return False, "Authentication failed — check SMTP_USER / SMTP_PASS"
    except Exception as e:                  return False, str(e)


def build_brief_email_html(user_name, profile_label, brief_text, threat_score, brief_level):
    lc = {"CRITICAL":"#ef4444","HIGH":"#f59e0b","ELEVATED":"#3b82f6","NOMINAL":"#22c55e"}
    c  = lc.get(brief_level, "#3b82f6")
    ps = "".join(f"<p style='margin:0 0 14px;line-height:1.8'>{p}</p>"
                 for p in brief_text.split("\n\n") if p.strip())
    return f"""<!DOCTYPE html><html><body style='background:#05070b;margin:0;padding:0;font-family:Georgia,serif'>
<div style='max-width:600px;margin:0 auto;padding:32px 20px'>
  <div style='border-bottom:1px solid #1a2e3e;padding-bottom:16px;margin-bottom:24px'>
    <span style='font-family:Arial,sans-serif;font-size:22px;letter-spacing:4px;color:#e8f2f8;font-weight:700'>ORION</span>
    <span style='font-family:monospace;font-size:9px;letter-spacing:2px;color:#3b82f6;border:1px solid rgba(59,130,246,.3);padding:2px 6px;margin-left:8px'>BRIEF</span>
    <span style='float:right;font-family:monospace;font-size:9px;color:{c};border:1px solid;border-color:{c}33;padding:2px 8px;background:{c}11'>{brief_level}</span>
  </div>
  <p style='font-family:monospace;font-size:8px;letter-spacing:1px;color:#3d5f78;margin:0 0 6px'>GOOD MORNING {user_name.upper()} · {profile_label.upper()} BRIEF</p>
  <p style='font-family:monospace;font-size:8px;color:#3d5f78;margin:0 0 24px'>{datetime.now(IST).strftime('%A, %d %B %Y')} · THREAT INDEX: <span style='color:{c}'>{threat_score}/100</span></p>
  <div style='background:#080d12;border:1px solid #1a2e3e;border-left:3px solid #3b82f6;padding:24px;color:#b8d0e0;font-size:15px;font-style:italic;line-height:1.85'>{ps}</div>
  <div style='margin-top:24px;padding-top:16px;border-top:1px solid #1a2e3e;font-family:monospace;font-size:8px;color:#3d5f78;text-align:center'>
    ORION BRIEF · SOUTH ASIA INTELLIGENCE · UNCLASSIFIED OSINT<br>
    <a href='{BASE_URL}/settings' style='color:#2a4458'>Manage email preferences</a>
  </div>
</div></body></html>"""


def send_morning_digests():
    """WL-03: Each user gets a brief generated with their own watchlist injected."""
    print("📧 Sending morning email digests...")
    users = get_users_with_email_digest()
    sent = failed = 0
    for user in users:
        if not is_subscription_active(user["id"]): continue
        profile  = user["profile"]
        pi       = PROFILES.get(profile, PROFILES["security"])
        # WL-03: generate a personalised brief for this user's watchlist
        wl = parse_watchlist(user.get("watchlist") or "")
        if wl:
            # Fresh personalised brief — not from shared cache
            brief_d = generate_brief_for_profile(profile, watchlist_items=wl)
        else:
            # No watchlist — use the shared cached brief
            brief_d = cache["briefs"].get(profile) or cache["briefs"].get("security") or {}
        brief = brief_d.get("brief","")
        if not brief: continue
        subject = f"ORION Brief — {datetime.now(IST).strftime('%d %b %Y')} [{brief_d.get('level','NOMINAL')}]"
        html    = build_brief_email_html(user["name"], pi["label"], brief,
                                         cache["threat_score"], brief_d.get("level","NOMINAL"))
        ok = send_email(user["email"], subject, html, brief, user_id=user["id"], email_type="digest")
        if ok: sent += 1
        else:  failed += 1
    print(f"✓ Digest complete — sent:{sent}  failed:{failed}")


def send_alert_email(to_email, user_name, rule_name, event_title, event_place, user_id):
    subject = f"⚠ ORION Alert: {rule_name} triggered"
    html    = f"""<!DOCTYPE html><html><body style='background:#05070b;font-family:Georgia,serif;padding:32px 20px'>
<div style='max-width:500px;margin:0 auto'>
  <div style='border-bottom:1px solid #1a2e3e;margin-bottom:20px;padding-bottom:12px'>
    <span style='font-family:Arial,sans-serif;font-size:20px;letter-spacing:4px;color:#e8f2f8;font-weight:700'>ORION</span>
    <span style='font-family:monospace;font-size:8px;color:#ef4444;border:1px solid #ef444433;padding:2px 6px;margin-left:8px'>⚠ ALERT TRIGGERED</span>
  </div>
  <p style='font-family:monospace;font-size:8px;color:#3d5f78;margin:0 0 16px'>ALERT FOR {user_name.upper()}</p>
  <div style='background:#1a0808;border:1px solid #ef444433;border-left:3px solid #ef4444;padding:20px'>
    <p style='font-family:monospace;font-size:9px;color:#ef4444;letter-spacing:1px;margin:0 0 8px'>RULE TRIGGERED: {rule_name}</p>
    <p style='color:#e8f2f8;font-size:14px;margin:0 0 8px'>{event_title}</p>
    <p style='font-family:monospace;font-size:8px;color:#5a7e96;margin:0'>◈ {event_place}</p>
  </div>
  <p style='font-family:monospace;font-size:7px;color:#2a4458;margin-top:20px;text-align:center'>ORION BRIEF · {datetime.now(IST).strftime('%d %b %Y %H:%M IST')}</p>
</div></body></html>"""
    return send_email(to_email, subject, html, f"ORION Alert — {rule_name}\n\n{event_title}\n{event_place}", user_id=user_id, email_type="alert")


def send_payment_confirmation_email(user_email, user_name, plan_name, amount_inr, inv_num=None):
    inv_link = f" · <a href='{BASE_URL}/invoice/{inv_num}' style='color:#3b82f6'>Download Invoice</a>" if inv_num else ""
    subject = f"✓ ORION Brief — Subscription Activated ({plan_name})"
    html    = f"""<!DOCTYPE html><html><body style='background:#05070b;font-family:Georgia,serif;padding:32px 20px'>
<div style='max-width:500px;margin:0 auto'>
  <p style='font-family:Arial,sans-serif;font-size:22px;letter-spacing:4px;color:#e8f2f8;font-weight:700'>ORION</p>
  <div style='background:#081408;border:1px solid #16a34a33;border-left:3px solid #22c55e;padding:20px;margin-top:16px'>
    <p style='font-family:monospace;font-size:9px;color:#22c55e;letter-spacing:1px;margin:0 0 8px'>✓ SUBSCRIPTION ACTIVATED</p>
    <p style='color:#e8f2f8;font-size:15px;margin:0 0 8px'>Welcome, {user_name}. Your {plan_name} subscription is now active.</p>
    <p style='font-family:monospace;font-size:8px;color:#5a7e96;margin:0'>₹{amount_inr:,}/month · Auto-renews monthly · <a href='{BASE_URL}' style='color:#3b82f6'>Access ORION Brief</a>{inv_link}</p>
  </div>
  <p style='font-family:monospace;font-size:7px;color:#2a4458;margin-top:20px'>ORION BRIEF · {datetime.now(IST).strftime('%d %b %Y %H:%M IST')}</p>
</div></body></html>"""
    send_email(user_email, subject, html, email_type="payment")


def send_renewal_email(user_email, user_name, plan_key, amount_inr, inv_num):
    """REC-02: Monthly renewal confirmation with invoice link."""
    plan_name = PLANS.get(plan_key, {}).get("name", plan_key.title())
    subject   = f"ORION Brief — Monthly Renewal Confirmed ({datetime.now(IST).strftime('%B %Y')})"
    html      = f"""<!DOCTYPE html><html><body style='background:#05070b;font-family:Georgia,serif;padding:32px 20px'>
<div style='max-width:500px;margin:0 auto'>
  <p style='font-family:Arial,sans-serif;font-size:22px;letter-spacing:4px;color:#e8f2f8;font-weight:700'>ORION</p>
  <div style='background:#080d12;border:1px solid #1a2e3e;border-left:3px solid #3b82f6;padding:20px;margin-top:16px'>
    <p style='font-family:monospace;font-size:9px;color:#3b82f6;letter-spacing:1px;margin:0 0 8px'>↻ MONTHLY RENEWAL PROCESSED</p>
    <p style='color:#e8f2f8;font-size:14px;margin:0 0 10px'>{user_name} — {plan_name} renewed for {datetime.now(IST).strftime('%B %Y')}.</p>
    <p style='font-family:monospace;font-size:8px;color:#5a7e96;margin:0 0 4px'>Amount charged: ₹{amount_inr:,} + 18% GST</p>
    <p style='font-family:monospace;font-size:8px;color:#5a7e96;margin:0'>
      <a href='{BASE_URL}/invoice/{inv_num}' style='color:#3b82f6;text-decoration:none'>Download GST Invoice {inv_num} →</a>
    </p>
  </div>
  <p style='font-family:monospace;font-size:7px;color:#2a4458;margin-top:20px'>ORION BRIEF · {datetime.now(IST).strftime('%d %b %Y %H:%M IST')}</p>
</div></body></html>"""
    send_email(user_email, subject, html, email_type="renewal")


def send_password_reset_email(to_email: str, user_name: str, reset_link: str):
    """PR-06: ORION-branded password reset email. Link expires in 1 hour."""
    subject = "ORION Brief — Password Reset Request"
    html    = f"""<!DOCTYPE html><html><body style='background:#05070b;margin:0;padding:0;font-family:Georgia,serif'>
<div style='max-width:500px;margin:0 auto;padding:32px 20px'>
  <div style='border-bottom:1px solid #1a2e3e;padding-bottom:16px;margin-bottom:24px'>
    <span style='font-family:Arial,sans-serif;font-size:22px;letter-spacing:4px;color:#e8f2f8;font-weight:700'>ORION</span>
    <span style='font-family:monospace;font-size:9px;letter-spacing:2px;color:#3b82f6;border:1px solid rgba(59,130,246,.3);padding:2px 6px;margin-left:8px'>BRIEF</span>
  </div>
  <p style='font-family:monospace;font-size:8px;letter-spacing:1px;color:#3d5f78;margin:0 0 6px'>PASSWORD RESET REQUEST FOR {user_name.upper()}</p>
  <p style='font-family:monospace;font-size:8px;letter-spacing:1px;color:#3d5f78;margin:0 0 24px'>{datetime.now(IST).strftime('%d %b %Y %H:%M IST')} · EXPIRES IN 1 HOUR</p>
  <div style='background:#080d12;border:1px solid #1a2e3e;border-left:3px solid #f59e0b;padding:24px;margin-bottom:24px'>
    <p style='color:#b8d0e0;font-size:14px;line-height:1.7;margin:0 0 20px'>
      A password reset was requested for your ORION Brief account.
      Click the button below to set a new password. This link expires in <strong style='color:#f59e0b'>1 hour</strong>.
    </p>
    <a href='{reset_link}' style='display:inline-block;background:#1d4ed8;color:#e8f2f8;font-family:monospace;font-size:9px;letter-spacing:2px;padding:12px 24px;text-decoration:none'>
      RESET PASSWORD →
    </a>
    <p style='font-family:monospace;font-size:7.5px;color:#3d5f78;margin:16px 0 0;word-break:break-all'>
      Or copy this link: {reset_link}
    </p>
  </div>
  <div style='font-family:monospace;font-size:8px;color:#2a4458;line-height:1.7'>
    If you did not request this reset, ignore this email — your password has not changed.<br>
    For security, this link can only be used once.
  </div>
  <div style='margin-top:24px;padding-top:16px;border-top:1px solid #1a2e3e;font-family:monospace;font-size:7px;color:#2a4458;text-align:center'>
    ORION BRIEF · SOUTH ASIA INTELLIGENCE · UNCLASSIFIED OSINT
  </div>
</div></body></html>"""
    plain = (f"ORION Brief — Password Reset\n\n"
             f"Hi {user_name},\n\n"
             f"Reset your password using this link (expires in 1 hour):\n{reset_link}\n\n"
             f"If you didn't request this, ignore this email.\n")
    return send_email(to_email, subject, html, plain, email_type="password_reset")


# ─────────────────────────────────────────────────────────────────────
# ALERT RULE ENGINE
# ─────────────────────────────────────────────────────────────────────

def check_alert_rules(events):
    rules = get_all_active_rules()
    if not rules or not events: return
    fired_rule_ids = set()
    fired = 0
    for rule in rules:
        rule_id = rule["id"]
        if rule_id in fired_rule_ids: continue
        if rule["last_triggered"]:
            try:
                last_dt = datetime.fromisoformat(rule["last_triggered"])
                if last_dt.tzinfo is None: last_dt = last_dt.replace(tzinfo=IST)
                if (datetime.now(IST) - last_dt).total_seconds() < 21600: continue
            except: pass
        matched = next((e for e in events if _rule_matches(rule, e)), None)
        if not matched: continue
        email_sent = error = False
        if SMTP_USER and SMTP_PASS:
            email_sent = send_alert_email(rule["email"], rule["name"], rule["name"],
                                          matched["title"], matched.get("place","Unknown"), rule["user_id"])
            if not email_sent: error = "SMTP send failed"
        mark_rule_triggered(rule_id, matched["title"], matched.get("place",""), email_sent, error)
        fired_rule_ids.add(rule_id); fired += 1
    if fired: print(f"✓ {fired} alert rule(s) triggered")


def _rule_matches(rule, event):
    field, operator, value = rule["field"], rule["operator"], str(rule["value"]).lower().strip()
    ev_val = {"place": (event.get("place") or "").lower(),
              "title": (event.get("title") or "").lower(),
              "score": event.get("score", 0),
              "type":  (event.get("type") or "").lower(),
              "source":(event.get("source") or "").lower()}.get(field, "")
    if operator == "contains":     return value in str(ev_val)
    if operator == "not_contains": return value not in str(ev_val)
    if operator == "gte":
        try: return float(ev_val) >= float(value)
        except: return False
    if operator == "lte":
        try: return float(ev_val) <= float(value)
        except: return False
    if operator == "equals":       return str(ev_val) == value
    return False


# ─────────────────────────────────────────────────────────────────────
# DATA FETCHERS — DQ fixes applied
# ─────────────────────────────────────────────────────────────────────

# DQ-01: signal and noise word lists
_SIGNAL_WORDS  = {"attack","strike","killed","fired","explosion","launched","seized","breach",
                  "troops","deployed","airstrikes","missile","clashes","offensive","violated",
                  "shelling","arrested","intercepted","sank","hijacked","detonated","crashed"}
_NOISE_WORDS   = {"opinion","analysis","discusses","says","talks","visited","speech","interview",
                  "column","review","editorial","report says","according to","speaks about",
                  "comments on","weighs in","reacts","statement on","warns of","calls for"}
_QUALITY_DOMAINS = {"reuters.com","bbc.co.uk","bbc.com","apnews.com","thehindu.com","ndtv.com",
                    "dawn.com","thenews.com.pk","hindustantimes.com","economictimes.indiatimes.com",
                    "livemint.com","firstpost.com","thewire.in","aljazeera.com","defensenews.com",
                    "janes.com","navalnews.com","maritime-executive.com","theprint.in"}


def _gdelt_score(title, url=""):
    """DQ-01 + DQ-03: compute signal quality score for a GDELT article."""
    t = title.lower()
    base   = 45
    signal = sum(10 for w in _SIGNAL_WORDS if w in t)
    noise  = sum(1 for phrase in _NOISE_WORDS if phrase in t)
    domain_bonus = 15 if any(d in (url or "") for d in _QUALITY_DOMAINS) else 0
    score  = min(95, base + signal + domain_bonus - noise * 12)
    return score


def _title_is_duplicate(new_title, existing_events, threshold=0.55):
    """DQ-02: fuzzy word-overlap dedup — skip if >55% word overlap with any existing event."""
    new_words = set(new_title.lower().split())
    if len(new_words) < 4: return False
    for ev in existing_events:
        ev_words = set((ev.get("title") or "").lower().split())
        if not ev_words: continue
        overlap = len(new_words & ev_words) / max(len(new_words | ev_words), 1)
        if overlap > threshold: return True
    return False


def fetch_usgs():
    try:
        r = requests.get("https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/4.5_day.geojson", timeout=10)
        events = []
        for f in (r.json().get("features") or [])[:8]:
            p, coords = f["properties"], f.get("geometry",{}).get("coordinates",[])
            mag  = p.get("mag",0) or 0
            near = len(coords)>=2 and 5<coords[1]<40 and 60<coords[0]<100
            events.append({
                "type":"earthquake","source":"USGS","confidence":"HIGH",
                "title":p.get("title","Earthquake event"),"place":p.get("place","Unknown"),
                "score":min(100,int((mag-4)*22)),"time":p.get("time",int(time.time()*1000)),
                "india_impact":"Seismic activity in India strategic zone" if near else "Regional seismic event",
            })
        return events
    except Exception as e: print(f"USGS error: {e}"); return []


def fetch_gdelt():
    """DQ-01 + DQ-02 + DQ-03 + DQ-04: filtered, deduped, scored GDELT events."""
    queries = [
        ("Pakistan+India+border+LoC+military",  "Pakistan/India LoC",  "Direct T1 border threat"),
        ("China+PLA+LAC+India+Arunachal",        "China LAC",           "PLA forward deployment threatens Ladakh and Arunachal Pradesh"),
        ("Houthi+Red+Sea+attack+ship",           "Red Sea / Aden",      "Houthi ops disrupting Indian shipping — Cape reroute adds 30% cost"),
        ("Iran+Hormuz+oil+tanker",               "Strait of Hormuz",    "80% of India oil here — closure triggers 7-day buffer"),
        ("India+Navy+IOR+China+PLAN",            "Indian Ocean",        "PLAN in India strategic backyard — String of Pearls expansion"),
        ("cyber+attack+India+CERT+vulnerability","Cyberspace",          "Active campaign targeting India critical infrastructure"),
    ]
    events = []
    for q, region, impact in queries:
        try:
            r = requests.get(
                f"https://api.gdeltproject.org/api/v2/doc/doc"
                f"?query={q}&mode=artlist&maxrecords=5&format=json&timespan=24h",
                timeout=10)
            for a in (r.json().get("articles") or []):
                title = (a.get("title") or "").strip()
                url   = a.get("url","")
                if not title or len(title) < 15: continue

                # DQ-01: noise word filter
                tl = title.lower()
                if any(phrase in tl for phrase in _NOISE_WORDS): continue

                # DQ-02: dedup
                if _title_is_duplicate(title, events): continue

                # DQ-01 + DQ-03: quality score
                score = _gdelt_score(title, url)

                # DQ-04: minimum threshold
                if score < 30: continue

                confidence = "HIGH" if score >= 65 else "MED" if score >= 45 else "LOW"
                events.append({
                    "type":"news","source":"GDELT","confidence":confidence,
                    "title":title,"place":region,"score":score,
                    "time": int(time.time()*1000) - random.randint(0, 43200000),
                    "india_impact":impact,
                    "url": url,
                })
        except Exception as e:
            print(f"GDELT error ({region}): {e}")
    return events


def fetch_cisa():
    try:
        r = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10)
        events = []
        for v in (r.json().get("vulnerabilities") or [])[:5]:
            events.append({
                "type":"cyber","source":"CISA KEV","confidence":"HIGH",
                "title":f"{v.get('cveID','CVE')}: {v.get('vulnerabilityName','')} — {v.get('vendorProject','')}",
                "place":"Cyberspace / Global",
                "score":80 if v.get("knownRansomwareCampaignUse")=="Known" else 62,
                "time":int(datetime.fromisoformat(v.get("dateAdded","2024-01-01")).timestamp()*1000),
                "india_impact":"Active exploit — Indian govt and critical infrastructure at immediate risk",
            })
        return events
    except Exception as e: print(f"CISA error: {e}"); return []


def fetch_reliefweb():
    try:
        params = {"appname":"orion-brief","limit":6,"sort[]":"date:desc",
                  "filter[field]":"country.iso3","filter[value][]":["PAK","IND","AFG","MMR","LKA","YEM","IRN","IRQ"]}
        r = requests.get("https://api.reliefweb.int/v1/reports", params=params, timeout=10)
        events = []
        for item in (r.json().get("data") or []):
            f = item.get("fields",{})
            events.append({
                "type":"humanitarian","source":"ReliefWeb UN","confidence":"MED",
                "title":f.get("title","Humanitarian report"),
                "place":((f.get("country") or [{"name":"South Asia"}])[0]).get("name","South Asia"),
                "score":40+random.randint(0,20),"time":int(time.time()*1000),
                "india_impact":"Humanitarian situation may require Indian diplomatic engagement",
            })
        return events
    except Exception as e: print(f"ReliefWeb error: {e}"); return []


def fetch_acled():
    """DATA-01: ACLED API — verified, coded conflict data for South Asia.
    Requires ACLED_API_KEY and ACLED_EMAIL env vars.
    Register free at: https://developer.acleddata.com/
    """
    if not ACLED_API_KEY or not ACLED_EMAIL:
        return []   # silently skip — key not configured
    ACLED_IMPACT = {
        "India":       "Direct India territorial event — escalation risk elevated",
        "Pakistan":    "T1 border threat — Pakistan conflict dynamic active",
        "Afghanistan": "Regional spillover — India-Afghanistan corridor affected",
        "Myanmar":     "India's eastern border — Manipur/Mizoram cascade risk",
    }
    try:
        params = {
            "key":        ACLED_API_KEY,
            "email":      ACLED_EMAIL,
            "country":    "India|Pakistan|Afghanistan|Myanmar",
            "limit":      20,
            "fields":     "event_date|event_type|sub_event_type|country|location|notes|fatalities|source",
            "format":     "json",
        }
        r = requests.get("https://api.acleddata.com/acled/read", params=params, timeout=15)
        r.raise_for_status()
        data   = r.json().get("data") or []
        events = []
        for ev in data:
            country  = ev.get("country", "South Asia")
            location = ev.get("location", country)
            etype    = ev.get("event_type", "Conflict")
            sub_type = ev.get("sub_event_type", "")
            fatalities = int(ev.get("fatalities") or 0)
            notes    = (ev.get("notes") or "")[:120]
            title    = f"{etype}: {sub_type} in {location}, {country}" if sub_type else f"{etype} in {location}, {country}"
            if notes and len(notes) > 20:
                title = notes[:100].rstrip() + ("…" if len(notes) >= 100 else "")

            # Score based on fatalities and event type
            base  = 55
            score = min(95, base + fatalities * 3 + (15 if "Explosion" in etype or "Violence" in etype else 0))
            # Dedup against existing events
            if _title_is_duplicate(title, events): continue

            events.append({
                "type":        "conflict",
                "source":      "ACLED",
                "confidence":  "HIGH",  # ACLED is hand-coded, highest confidence
                "title":       title,
                "place":       f"{location}, {country}",
                "score":       score,
                "time":        int(time.time() * 1000) - random.randint(0, 43200000),
                "india_impact": ACLED_IMPACT.get(country, "Regional conflict — monitor for India cascade"),
                "fatalities":  fatalities,
            })
        print(f"✓ ACLED: {len(events)} conflict events")
        return events
    except requests.HTTPError as e:
        print(f"ACLED HTTP error: {e.response.status_code} — check ACLED_API_KEY / ACLED_EMAIL"); return []
    except Exception as e:
        print(f"ACLED error: {e}"); return []


def fetch_newsapi():
    """DATA-02: NewsAPI — current English-language news with same DQ pipeline as GDELT.
    Requires NEWSAPI_KEY env var.
    Free tier: 100 requests/day — sufficient for our 1 fetch/day pattern.
    Register at: https://newsapi.org/register
    """
    if not NEWSAPI_KEY:
        return []   # silently skip — key not configured
    queries = [
        ("India Pakistan border military LoC",  "Pakistan/India LoC",  "Direct T1 border threat"),
        ("China India LAC Ladakh PLA",           "China LAC",           "PLA posture at LAC friction points"),
        ("Houthi Red Sea attack shipping",       "Red Sea / Aden",      "Houthi ops disrupting Indian shipping"),
        ("Iran Hormuz oil tanker",               "Strait of Hormuz",    "80% of India oil transits Hormuz"),
        ("India cyber attack ransomware CERT",   "Cyberspace",          "Active campaign targeting India critical infrastructure"),
        ("India Navy IOR China PLAN warship",    "Indian Ocean",        "PLAN presence in India strategic backyard"),
    ]
    events = []
    for q, region, impact in queries:
        try:
            params = {
                "q":        q,
                "language": "en",
                "sortBy":   "relevance",
                "pageSize": 5,
                "from":     (datetime.now(IST) - timedelta(hours=36)).strftime("%Y-%m-%dT%H:%M:%S"),
                "apiKey":   NEWSAPI_KEY,
            }
            r = requests.get("https://newsapi.org/v2/everything", params=params, timeout=10)
            r.raise_for_status()
            for a in (r.json().get("articles") or []):
                title  = ((a.get("title") or "").split(" - ")[0]).strip()  # strip source suffix
                url    = a.get("url","")
                source = (a.get("source") or {}).get("name","")
                if not title or len(title) < 15: continue
                tl = title.lower()
                if any(phrase in tl for phrase in _NOISE_WORDS): continue
                if _title_is_duplicate(title, events): continue
                score = _gdelt_score(title, url)
                if score < 30: continue
                confidence = "HIGH" if score >= 65 else "MED" if score >= 45 else "LOW"
                events.append({
                    "type":"news","source":f"NewsAPI/{source}" if source else "NewsAPI",
                    "confidence":confidence,"title":title,"place":region,"score":score,
                    "time":int(time.time()*1000) - random.randint(0,43200000),
                    "india_impact":impact,"url":url,
                })
        except requests.HTTPError as e:
            code = e.response.status_code
            if code == 426:
                print("NewsAPI: free tier upgrade required — skipping"); return events
            print(f"NewsAPI error ({region}): HTTP {code}")
        except Exception as e:
            print(f"NewsAPI error ({region}): {e}")
    if events: print(f"✓ NewsAPI: {len(events)} events")
    return events


def is_non_english(text):
    if not text: return False
    nl = sum(1 for c in text if ord(c)>0x024F and not(0x1E00<=ord(c)<=0x1EFF))
    return (nl/max(len(text),1)) > 0.15


def translate_events(events):
    if not client: return events
    to_tr = [e for e in events if is_non_english(e.get("title",""))]
    if not to_tr: return events
    try:
        msg = client.messages.create(model="claude-sonnet-4-20250514", max_tokens=800,
            messages=[{"role":"user","content":
                "Translate to English. Return ONLY JSON array, same order, no markdown.\n\n" +
                "\n".join(f"{i+1}. {e['title']}" for i,e in enumerate(to_tr))}])
        translations = json.loads(msg.content[0].text.strip())
        for i,e in enumerate(to_tr):
            if i < len(translations):
                e["original_title"]=e["title"]; e["title"]=translations[i]; e["translated"]=True
        print(f"✓ Translated {len(to_tr)} events")
    except Exception as err: print(f"Translation error: {err}")
    return events


def load_all_data():
    """DATA-04: Pull from 6 sources — USGS, GDELT, CISA, ReliefWeb, ACLED, NewsAPI."""
    print("↻ Fetching live data...")
    all_events = []
    # Always-on sources (no API key needed)
    for fn in [fetch_usgs, fetch_gdelt, fetch_cisa, fetch_reliefweb]:
        all_events.extend(fn())
    # Optional sources — gracefully skipped if keys absent
    acled_events = fetch_acled()
    news_events  = fetch_newsapi()
    all_events.extend(acled_events)
    all_events.extend(news_events)
    if acled_events: print(f"  + ACLED: {len(acled_events)} events")
    if news_events:  print(f"  + NewsAPI: {len(news_events)} events")
    all_events = [e for e in all_events if e and e.get("title")]
    all_events.sort(key=lambda e: e.get("score",0), reverse=True)
    all_events = translate_events(all_events)
    top5   = all_events[:5]
    threat = int(sum(e.get("score",0) for e in top5)/max(len(top5),1)) if top5 else 0
    level  = "CRITICAL" if threat>=75 else "HIGH" if threat>=55 else "ELEVATED" if threat>=35 else "NOMINAL"
    cache.update(events=all_events, threat_score=threat, brief_level=level,
                 last_fetch=datetime.now(IST).strftime("%H:%M IST, %d %b %Y"))
    check_alert_rules(all_events)
    sources = set(e.get("source","?").split("/")[0] for e in all_events)
    print(f"✓ {len(all_events)} events | Sources: {', '.join(sorted(sources))} | Threat {threat} ({level})")
    return all_events


# ─────────────────────────────────────────────────────────────────────
# BRIEF GENERATOR
# ─────────────────────────────────────────────────────────────────────

DEMO_BRIEFS = {
    "maritime": """[06:00 IST] Gulf of Aden remains CRITICAL with Houthi anti-ship operations against commercial traffic transiting Bab-el-Mandeb. Three Indian-flagged vessels rerouted via Cape of Good Hope this week, adding 30% to freight costs on India-Europe trade lanes.

IOR naval posture reflects intensifying competition: PLAN research vessel operations in the Andaman Sea — 200nm from India's strategic Andaman and Nicobar Command. India Navy Eastern Fleet shadowed throughout the transit.

Strait of Hormuz at ELEVATED risk — IRGC conducted harassment operations against UAE-bound tankers past 72 hours. 80% of India crude imports transit this corridor, making Iranian signalling a direct economic threat.

Malacca Strait remains NOMINAL with standard vessel density. However PLAN submarine activity near Lombok Strait suggests pre-positioning for potential chokepoint pressure on alternative deep-water routing.

Cascade shipping risk: Baltic Dry Index elevated 18% week-on-week as Red Sea avoidance forces global rerouting. India import cost pressure on fertiliser, crude, and containers continues to compound into Q2.""",
    "cyber": """[06:00 IST] CISA KEV issued two critical advisories — CVE-2024-3400 affecting Palo Alto PAN-OS and Cisco IOS XE zero-day with active exploitation confirmed. Both widely deployed across Indian government ministries and BFSI sector — immediate patch urgency 24-48 hours.

CERT-In has not issued corresponding advisory, leaving Indian organisations in maximum-exposure window. Palo Alto vulnerability affects GlobalProtect VPN used by multiple Indian defence PSUs — recommend immediate firewall isolation pending patch.

AbuseCH ThreatFox tracking Cobalt Strike C2 cluster with confirmed targeting of Indian financial sector domains. Infrastructure shares TTPs with APT41 — China-nexus actor known for India BFSI and telecom targeting.

Ransomware activity elevated — LockBit 3.0 affiliate operating against Indian manufacturing sector, two confirmed incidents in Pune industrial corridor. Campaign leverages unpatched Cisco vulnerability as initial access vector.

Hybrid signal: Coordinated cyber reconnaissance of Indian border area telecom infrastructure detected simultaneously with PLA LAC activity — pattern consistent with pre-escalation information operations doctrine.""",
}
for pk in PROFILES:
    if pk not in DEMO_BRIEFS: DEMO_BRIEFS[pk] = DEMO_BRIEFS["maritime"]


def parse_watchlist(raw: str) -> list[str]:
    """WL-02: Convert raw watchlist string to clean list of non-empty terms."""
    if not raw: return []
    return [w.strip() for w in raw.replace(",", "\n").splitlines() if w.strip()]


def _watchlist_section(watchlist_items: list[str], profile_label: str) -> str:
    """WL-02: Build the watchlist injection block for the brief prompt."""
    if not watchlist_items:
        return ""
    items_str = " · ".join(watchlist_items)
    return f"""
CLIENT WATCHLIST — MANDATORY COVERAGE:
This client has flagged the following specific assets, routes, companies, or regions for priority monitoring:
  {items_str}

You MUST explicitly reference at least 2–3 of these watchlist items by name in your brief.
If live data directly involves a watchlist item, lead that paragraph with it.
If no live event directly matches, include a 1-sentence status update for each watchlist item
  (e.g. "MV Jag Anand — no incidents reported in IOR in last 24 hours, route NOMINAL.").
Frame every watchlist reference through its specific operational impact on the {profile_label} client."""


def generate_brief_for_profile(profile_key, watchlist_items=None):
    """WL-02 + WL-03: Generate profile brief, injecting client watchlist into prompt."""
    profile = PROFILES.get(profile_key, PROFILES["security"])
    events  = cache["events"] or []
    wl      = watchlist_items or []

    if not client:
        result = {"brief": DEMO_BRIEFS.get(profile_key, DEMO_BRIEFS["maritime"]),
                  "time":  datetime.now(IST).strftime("%H:%M IST, %d %b %Y"),
                  "level": cache["brief_level"]}
        cache["briefs"][profile_key] = result
        return result

    focus    = profile["focus"]
    # WL-02: boost events that match watchlist terms — they surface to the top
    def _event_score(e):
        base = e.get("score", 0)
        if wl:
            text = (e.get("title","") + " " + e.get("place","")).lower()
            if any(w.lower() in text for w in wl):
                base += 25   # watchlist match bonus — pushes into top_ev
        return base

    relevant = [e for e in events if any(w in (e.get("place","") + e.get("title","")).lower()
                                         for w in focus)]
    pool     = relevant or events
    pool_sorted = sorted(pool, key=_event_score, reverse=True)
    top_ev   = pool_sorted[:10]

    nl = chr(10)
    prompt = f"""You are ORION, a South Asia strategic intelligence analyst.
Generate a personalised morning brief for a {profile['label']} professional.

PROFILE DIRECTIVE: {profile['brief_directive']}
{_watchlist_section(wl, profile['label'])}
LIVE DATA ({datetime.utcnow().strftime('%d %b %Y %H:%M UTC')}):
{nl.join(f'- [{e["source"]}][{e.get("confidence","?")}] {e["title"]} [{e["place"]}] Score:{e.get("score","?")}' for e in top_ev)}

THREAT INDEX: {cache["threat_score"]}/100

5 paragraphs covering: {', '.join(profile['topics'])}.
2-3 sentences each. Start with [{datetime.now(IST).strftime('%H:%M')} IST].
180-220 words. Each paragraph ends with India-specific impact for {profile['label']}.
No bullets. Use only HIGH and MED confidence events for key claims."""

    try:
        msg   = client.messages.create(model="claude-sonnet-4-20250514", max_tokens=650,
                                       messages=[{"role": "user", "content": prompt}])
        brief = msg.content[0].text
        score = cache["threat_score"]
        level = "CRITICAL" if score >= 75 else "HIGH" if score >= 55 else "ELEVATED" if score >= 35 else "NOMINAL"
        result = {"brief": brief, "time": datetime.now(IST).strftime("%H:%M IST, %d %b %Y"), "level": level}
        cache["briefs"][profile_key] = result
        wl_note = f" [watchlist: {len(wl)} items]" if wl else ""
        print(f"✓ Brief: {profile_key}{wl_note}")
        return result
    except Exception as e:
        print(f"Brief error ({profile_key}): {e}")
        fb = DEMO_BRIEFS.get(profile_key, DEMO_BRIEFS["maritime"])
        result = {"brief": fb, "time": datetime.now(IST).strftime("%H:%M IST"), "level": cache["brief_level"]}
        cache["briefs"][profile_key] = result
        return result


def generate_all_briefs():
    """Nightly cache refresh — no watchlist (shared cache). Per-user watchlist
    injected at request time in api_brief and send_morning_digests."""
    print("↻ Generating all profile briefs (no watchlist — shared cache)...")
    for pk in PROFILES:
        generate_brief_for_profile(pk, watchlist_items=None)
    _save_briefs_to_disk()
    print(f"✓ {len(PROFILES)} profile briefs ready")


def _save_briefs_to_disk():
    try:
        CACHE_FILE.write_text(json.dumps({"briefs":cache["briefs"],"threat_score":cache["threat_score"],
                                          "brief_level":cache["brief_level"],"saved_at":datetime.now(IST).isoformat()},indent=2))
    except Exception as e: print(f"Disk save error: {e}")


def _load_briefs_from_disk():
    if not CACHE_FILE.exists(): return False
    try:
        d = json.loads(CACHE_FILE.read_text())
        cache["briefs"]=d.get("briefs",{}); cache["threat_score"]=d.get("threat_score",0)
        cache["brief_level"]=d.get("brief_level","NOMINAL")
        print(f"✓ Loaded {len(cache['briefs'])} briefs from disk"); return True
    except Exception as e: print(f"Disk load error: {e}"); return False


# ─────────────────────────────────────────────────────────────────────
# NLQ
# ─────────────────────────────────────────────────────────────────────

def ask_orion(question, profile_key="security", watchlist_items=None):
    """WL-02: NLQ with optional watchlist context — prioritises client assets in answers."""
    profile = PROFILES.get(profile_key, PROFILES["security"])
    if not client: return _demo_answer(question)
    events = cache["events"] or []
    if not events: load_all_data(); events = cache["events"]
    # WL-02: boost watchlist-matching events to top of NLQ context
    wl = watchlist_items or []
    if wl:
        wl_lower = [w.lower() for w in wl]
        def wl_score(e):
            combined = (e.get("title","") + " " + e.get("place","")).lower()
            return sum(1 for w in wl_lower if w in combined)
        events = sorted(events, key=lambda e: (wl_score(e), e.get("score", 0)), reverse=True)
    context = "\n".join(
        f"[{e['source']}][{e.get('confidence','?')}] {e['title']} — {e['place']} (Score:{e.get('score','?')}) India: {e.get('india_impact','')}"
        for e in events[:12])
    # WL-02: prepend watchlist context so Claude knows what to prioritise
    wl_note = ""
    if wl:
        wl_note = (f"\nCLIENT WATCHLIST (assets/routes this client is specifically tracking): "
                   f"{' · '.join(wl)}\n"
                   f"If the question or any live event touches a watchlist item, mention it by name "
                   f"in your answer and give its specific status.\n")
    try:
        msg = client.messages.create(model="claude-sonnet-4-20250514", max_tokens=400,
            messages=[{"role":"user","content":
                f"You are ORION, a senior South Asia intelligence analyst specialising in {profile['label']}.\n"
                f"{wl_note}"
                f"LIVE DATA ({datetime.utcnow().strftime('%d %b %Y %H:%M UTC')}):\n{context}\n\n"
                f"QUESTION: \"{question}\"\n\n"
                f"3-5 sentences for a {profile['label']} professional. "
                f"Analyst tone. India-specific impact. No bullets."}])
        return msg.content[0].text
    except Exception as e: print(f"NLQ error: {e}"); return _demo_answer(question)


def _demo_answer(q):
    ql = q.lower()
    if any(w in ql for w in ["pakistan","border","loc"]): return "Pakistan-India LoC remains ELEVATED. ACLED data shows small-arms activity in Poonch-Rajouri. Cold Start triggers not met but forward deployment posture suggests readiness."
    if any(w in ql for w in ["red sea","houthi","shipping"]): return "Red Sea is the most operationally significant chokepoint disruption for Indian trade. Houthi ops diverted 80%+ traffic — Indian carriers via Cape of Good Hope adding 12-14 transit days and 30-40% cost premium."
    if any(w in ql for w in ["china","ior","naval"]): return "PLAN presence in IOR has increased materially. Research vessels and submarine support ships tracked in Andaman Sea. India MDA gap in southern IOR remains the primary vulnerability."
    if any(w in ql for w in ["cyber","cisa"]): return "Cyber threat environment targeting India is HIGH. CISA KEV flagged critical RCE in Cisco IOS XE and Palo Alto PAN-OS — both widely deployed in Indian government networks."
    return f"Current ORION threat index: {cache['threat_score']}/100. Primary concerns — T1 LoC/LAC, T2 Red Sea, active cyber campaigns against India."


# ─────────────────────────────────────────────────────────────────────
# FLASK ROUTES — AUTH
# ─────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET","POST"])
def login_page():
    if "user_id" in session: return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        user = get_user_by_email(request.form.get("email","").strip())
        if user and user["password_hash"] == hash_password(request.form.get("password","")):
            session.clear(); session.permanent=True; session["user_id"]=user["id"]
            update_last_login(user["id"])
            return redirect(url_for("index"))
        error = "Invalid email or password"
    return render_template("login.html", error=error, profiles=PROFILES)


@app.route("/register", methods=["GET","POST"])
def register_page():
    if "user_id" in session: return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        name=request.form.get("name","").strip(); email=request.form.get("email","").strip()
        password=request.form.get("password",""); profile=request.form.get("profile","maritime")
        if not name or not email or not password: error="All fields required"
        elif len(password)<8: error="Password must be 8+ characters"
        elif profile not in PROFILES: error="Invalid profile"
        else:
            ok,err = create_user(email, password, name, profile)
            if ok:
                user = get_user_by_email(email)
                session.clear(); session.permanent=True; session["user_id"]=user["id"]
                return redirect(url_for("subscribe_page"))
            error = err
    return render_template("register.html", error=error, profiles=PROFILES)


@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login_page"))


# ─────────────────────────────────────────────────────────────────────
# PASSWORD RESET — PR-07 + PR-08
# ─────────────────────────────────────────────────────────────────────

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password_page():
    """PR-07: Step 1 — user enters email. Always show success message (anti-enumeration)."""
    if "user_id" in session:
        return redirect(url_for("index"))

    sent = False
    error = None

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email:
            error = "Email address is required"
        else:
            user = get_user_by_email(email)
            if user:
                # Only send if SMTP is configured — silently skip otherwise (logs show)
                if SMTP_USER and SMTP_PASS:
                    raw_token  = create_reset_token(user["id"])
                    reset_link = f"{BASE_URL}/reset-password/{raw_token}"
                    ok = send_password_reset_email(user["email"], user["name"], reset_link)
                    if not ok:
                        print(f"⚠ Password reset email failed for {email} — check SMTP config")
                else:
                    # Dev / no-SMTP mode: print the link to server logs for testing
                    raw_token  = create_reset_token(user["id"])
                    reset_link = f"{BASE_URL}/reset-password/{raw_token}"
                    print(f"[DEV] Password reset link for {email}: {reset_link}")
            # Always show success — never reveal whether email is registered
            sent = True

    return render_template("forgot_password.html", sent=sent, error=error)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password_page(token):
    """PR-08: Step 2 — user sets new password using the token from their email."""
    if "user_id" in session:
        return redirect(url_for("index"))

    token_row = get_valid_reset_token(token)
    if not token_row:
        # Token invalid, expired, or already used
        return render_template("reset_password.html", invalid=True, done=False, error=None)

    error = None
    if request.method == "POST":
        password  = request.form.get("password", "")
        password2 = request.form.get("password2", "")
        if len(password) < 8:
            error = "Password must be at least 8 characters"
        elif password != password2:
            error = "Passwords do not match"
        else:
            update_password(token_row["user_id"], password)
            consume_reset_token(token_row["id"], token_row["user_id"])
            print(f"✓ Password reset for user_id={token_row['user_id']}")
            return render_template("reset_password.html", invalid=False, done=True, error=None)

    return render_template("reset_password.html", invalid=False, done=False, error=error)

@app.route("/subscribe")
@login_required
def subscribe_page():
    user = current_user()
    sub  = get_subscription(user["id"])
    return render_template("subscribe.html", user=dict(user), plans=PLANS,
                           sub=dict(sub) if sub else None,
                           razorpay_key=RAZORPAY_KEY_ID,
                           base_url=BASE_URL)


@app.route("/api/payment/create-order", methods=["POST"])
@login_required
def api_create_order():
    """Fallback one-time order (used when Razorpay Subscriptions API is not set up)."""
    user = current_user()
    data = request.get_json() or {}
    plan_key = data.get("plan","brief")
    if plan_key not in PLANS: return jsonify({"error":"Invalid plan"}), 400
    plan    = PLANS[plan_key]
    receipt = f"orion_{user['id']}_{plan_key}_{int(time.time())}"
    order   = razorpay_create_order(plan["price_paise"], receipt,
                                    {"user_id":str(user["id"]),"plan":plan_key,"email":user["email"]})
    if not order: return jsonify({"error":"Failed to create payment order"}), 500
    return jsonify({
        "order_id":      order["id"],
        "amount":        plan["price_paise"],
        "currency":      "INR",
        "plan_key":      plan_key,
        "plan_name":     plan["name"],
        "key":           RAZORPAY_KEY_ID,
        "prefill_name":  user["name"],
        "prefill_email": user["email"],
        "mode":          "one_time",
    })


@app.route("/api/payment/create-subscription", methods=["POST"])
@login_required
def api_create_subscription():
    """REC-01: Create Razorpay Subscription for auto-recurring monthly billing."""
    user = current_user()
    data = request.get_json() or {}
    plan_key = data.get("plan","brief")
    if plan_key not in PLANS: return jsonify({"error":"Invalid plan"}), 400
    sub_data, err = razorpay_create_subscription(plan_key, user["email"], user["name"])
    if not sub_data: return jsonify({"error": err or "Failed to create subscription"}), 500
    plan = PLANS[plan_key]
    return jsonify({
        "subscription_id": sub_data["id"],
        "amount":          plan["price_paise"],
        "currency":        "INR",
        "plan_key":        plan_key,
        "plan_name":       plan["name"],
        "key":             RAZORPAY_KEY_ID,
        "prefill_name":    user["name"],
        "prefill_email":   user["email"],
        "short_url":       sub_data.get("short_url",""),
        "mode":            "recurring",
    })


@app.route("/api/payment/verify", methods=["POST"])
@login_required
def api_verify_payment():
    """Verify payment after Razorpay checkout (both one-time and first subscription charge)."""
    user = current_user()
    data = request.get_json() or {}
    order_id   = data.get("razorpay_order_id","")
    payment_id = data.get("razorpay_payment_id","")
    signature  = data.get("razorpay_signature","")
    sub_id     = data.get("razorpay_subscription_id","")  # present for subscription flow
    plan_key   = data.get("plan_key","brief")
    if not payment_id: return jsonify({"error":"Missing payment details"}), 400
    # For subscription flow, signature body is sub_id|payment_id
    if sub_id:
        if RAZORPAY_SECRET:
            body     = f"{sub_id}|{payment_id}"
            expected = hmac.new(RAZORPAY_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature):
                return jsonify({"error":"Subscription payment verification failed"}), 400
    else:
        if not razorpay_verify_signature(order_id, payment_id, signature):
            return jsonify({"error":"Payment verification failed — possible fraud"}), 400
    plan = PLANS.get(plan_key, PLANS["brief"])
    create_subscription(user["id"], plan_key, plan["price_paise"],
                        order_id or None, payment_id,
                        razorpay_sub_id=sub_id or None,
                        billing_cycle="recurring" if sub_id else "one_time")
    # Create first invoice
    inv_num = create_invoice(user["id"], plan_key, plan["price_paise"], payment_id=payment_id,
                             razorpay_sub_id=sub_id or None)
    send_payment_confirmation_email(user["email"], user["name"], plan["name"],
                                    plan["price_inr"], inv_num)
    print(f"✓ Subscription activated: {user['email']} → {plan_key} | Invoice {inv_num}")
    return jsonify({"ok":True,"message":f"{plan['name']} subscription activated",
                    "invoice":inv_num,"redirect":"/"})


@app.route("/api/payment/webhook", methods=["POST"])
def api_payment_webhook():
    """REC-02 + REC-04: Razorpay webhook — handles auto-renewal charged + cancellations.
    Configure in Razorpay dashboard → Settings → Webhooks → add URL: {BASE_URL}/api/payment/webhook
    Events to enable: subscription.charged, subscription.cancelled, subscription.expired
    """
    raw_body   = request.get_data()
    header_sig = request.headers.get("X-Razorpay-Signature","")
    # REC-04: verify webhook signature
    if not razorpay_verify_webhook_signature(raw_body, header_sig):
        print("⚠ Webhook: invalid signature"); return jsonify({"error":"Invalid signature"}), 400
    try:
        payload   = json.loads(raw_body)
        event     = payload.get("event","")
        print(f"→ Razorpay webhook: {event}")
        if event == "subscription.charged":
            threading.Thread(target=handle_webhook_charged, args=(payload,), daemon=True).start()
        elif event in ("subscription.cancelled","subscription.expired","subscription.halted"):
            threading.Thread(target=handle_webhook_cancelled, args=(payload,), daemon=True).start()
        return jsonify({"ok":True}), 200
    except Exception as e:
        print(f"Webhook error: {e}"); return jsonify({"error":str(e)}), 500


@app.route("/api/payment/cancel-subscription", methods=["POST"])
@login_required
def api_cancel_subscription():
    """Cancel auto-recurring subscription at end of current billing cycle."""
    user = current_user()
    sub  = get_subscription(user["id"])
    if not sub: return jsonify({"error":"No active subscription"}), 400
    sub_id = sub.get("razorpay_sub_id")
    if sub_id and not sub_id.startswith("demo_") and RAZORPAY_KEY_ID:
        data, err = razorpay_cancel_subscription(sub_id, cancel_at_cycle_end=True)
        if not data: return jsonify({"error": err or "Cancel failed"}), 500
    else:
        # Manual cancel for one-time or demo subscriptions
        with get_db() as db:
            db.execute("UPDATE subscriptions SET status='cancelled' WHERE user_id=?", (user["id"],)); db.commit()
    return jsonify({"ok":True,"message":"Subscription will cancel at end of current billing period"})


# ── MAIN DASHBOARD ────────────────────────────────────────────────────

@app.route("/")
@subscription_required
def index():
    user = current_user()
    pi   = PROFILES.get(user["profile"], PROFILES["security"])
    sub  = get_subscription(user["id"])
    return render_template("index.html", user=dict(user), profile=pi,
                           profiles=PROFILES, profile_key=user["profile"],
                           sub=dict(sub) if sub else None, plans=PLANS,
                           admin_email=ADMIN_EMAIL)


@app.route("/health")
def health(): return jsonify({"status":"ok","service":"orion-brief","version":"6"}), 200


# ─────────────────────────────────────────────────────────────────────
# ADMIN PANEL — ADM-01 + ADM-02 + ADM-03
# ─────────────────────────────────────────────────────────────────────

@app.route("/admin")
@admin_required
def admin_panel():
    users     = get_all_users_for_admin()
    subs      = get_all_subscriptions()
    del_stats = get_email_delivery_stats()
    alert_log = get_all_alert_log_admin(limit=30)
    # Revenue calculation
    active_subs = [s for s in subs if s["status"]=="active"]
    mrr_paise   = sum(s["amount_paise"] for s in active_subs)
    return render_template("admin.html",
        users=     [dict(u) for u in users],
        subs=      [dict(s) for s in active_subs],
        del_stats= [dict(d) for d in del_stats],
        alert_log= [dict(a) for a in alert_log],
        mrr=       mrr_paise // 100,   # paise → rupees
        total_users=   len(users),
        active_clients=len(active_subs),
        cache=     cache,
        profiles=  PROFILES,
        plans=     PLANS,
        admin_email=ADMIN_EMAIL,
    )


@app.route("/api/admin/users")
@admin_required
def api_admin_users():
    users = get_all_users_for_admin()
    return jsonify({"users":[dict(u) for u in users]})


@app.route("/api/admin/revenue")
@admin_required
def api_admin_revenue():
    subs = get_all_subscriptions()
    active = [s for s in subs if s["status"]=="active"]
    return jsonify({
        "mrr_rupees":      sum(s["amount_paise"] for s in active) // 100,
        "active_clients":  len(active),
        "total_clients":   len(subs),
        "plan_breakdown":  {p: sum(1 for s in active if s["plan"]==p) for p in PLANS},
    })


@app.route("/api/admin/delivery")
@admin_required
def api_admin_delivery():
    stats = get_email_delivery_stats()
    return jsonify({"stats":[dict(s) for s in stats]})


@app.route("/api/admin/alerts")
@admin_required
def api_admin_alerts():
    logs = get_all_alert_log_admin(50)
    return jsonify({"logs":[dict(l) for l in logs]})


@app.route("/api/admin/users/<int:uid>/grant", methods=["POST"])
@admin_required
def api_admin_grant(uid):
    """Admin can manually grant subscription (for demos, trials)."""
    data     = request.get_json() or {}
    plan_key = data.get("plan","brief")
    if plan_key not in PLANS: return jsonify({"error":"Invalid plan"}), 400
    plan = PLANS[plan_key]
    create_subscription(uid, plan_key, 0, "admin_grant", "admin_grant")
    return jsonify({"ok":True,"message":f"Subscription granted: {plan_key}"})


@app.route("/api/admin/users/<int:uid>/revoke", methods=["POST"])
@admin_required
def api_admin_revoke(uid):
    sub = get_subscription(uid)
    # Cancel on Razorpay too if recurring
    if sub and sub.get("razorpay_sub_id") and RAZORPAY_KEY_ID:
        razorpay_cancel_subscription(sub["razorpay_sub_id"], cancel_at_cycle_end=False)
    with get_db() as db:
        db.execute("UPDATE subscriptions SET status='cancelled' WHERE user_id=?", (uid,)); db.commit()
    return jsonify({"ok":True})


# ─────────────────────────────────────────────────────────────────────
# INVOICES — INV-01 .. INV-04
# ─────────────────────────────────────────────────────────────────────

@app.route("/invoice/<inv_num>")
@login_required
def invoice_page(inv_num):
    """INV-02: Branded GST invoice — open in browser, Ctrl+P to download as PDF."""
    user    = current_user()
    invoice = get_invoice_by_number(inv_num)
    if not invoice: return "Invoice not found", 404
    # INV-03: only own invoices (or admin can see all)
    if invoice["user_id"] != user["id"] and user["email"].lower() != ADMIN_EMAIL:
        return "Access denied", 403
    plan_name = PLANS.get(invoice["plan"], {}).get("name", invoice["plan"].title())
    return render_template("invoice.html",
        invoice=dict(invoice), plan_name=plan_name,
        business_name=BUSINESS_NAME, business_addr=BUSINESS_ADDR,
        gst_number=GST_NUMBER, base_url=BASE_URL)


@app.route("/api/invoices")
@login_required
def api_user_invoices():
    user = current_user()
    invs = get_user_invoices(user["id"])
    return jsonify({"invoices": [dict(i) for i in invs]})


@app.route("/api/admin/invoices")
@admin_required
def api_admin_invoices():
    invs = get_all_invoices_admin()
    return jsonify({"invoices": [dict(i) for i in invs]})


# ── STANDARD API ──────────────────────────────────────────────────────

@app.route("/api/status")
@login_required
def api_status():
    now_ist  = datetime.now(IST)
    next_6am = now_ist.replace(hour=6,minute=0,second=0,microsecond=0)
    if now_ist >= next_6am: next_6am += timedelta(days=1)
    diff = next_6am - now_ist
    h,r = divmod(int(diff.total_seconds()),3600); m=r//60
    label = f"Next auto-refresh in {h}h {m}m (06:00 IST)"
    cache["next_refresh"]=label
    user = current_user()
    sub  = get_subscription(user["id"]) if user else None
    return jsonify({
        "threat_score":  cache["threat_score"],
        "brief_level":   cache["brief_level"],
        "last_fetch":    cache["last_fetch"],
        "event_count":   len(cache["events"]),
        "next_refresh":  label,
        "profile":       user["profile"] if user else "",
        "has_key":       bool(ANTHROPIC_KEY),
        "smtp_ready":    bool(SMTP_USER and SMTP_PASS),
        "razorpay_ready":bool(RAZORPAY_KEY_ID),
        "plan":          sub["plan"] if sub else "none",
    })


@app.route("/api/brief")
@subscription_required
def api_brief():
    user    = current_user()
    pk      = request.args.get("profile", user["profile"])
    if pk not in PROFILES: pk = user["profile"]
    refresh = request.args.get("refresh","0") == "1"
    # WL-03: parse this user's watchlist — if they have one, always generate personalised brief
    wl      = parse_watchlist(user.get("watchlist") or "")
    has_wl  = bool(wl)
    if refresh or pk not in cache["briefs"] or has_wl:
        if not cache["events"]: load_all_data()
        result = generate_brief_for_profile(pk, watchlist_items=wl)
    else:
        result = cache["briefs"][pk]
    return jsonify({"brief":result.get("brief",""),"brief_time":result.get("time",""),
                    "brief_level":result.get("level",cache["brief_level"]),
                    "threat_score":cache["threat_score"],"next_refresh":cache["next_refresh"],
                    "profile":pk,"profile_label":PROFILES[pk]["label"],
                    "watchlist_active": has_wl, "watchlist_count": len(wl)})


@app.route("/api/alerts")
@subscription_required
def api_alerts():
    if request.args.get("refresh","0")=="1" or not cache["events"]: load_all_data()
    return jsonify({"events":cache["events"][:5],"threat_score":cache["threat_score"],
                    "brief_level":cache["brief_level"],"last_fetch":cache["last_fetch"]})


@app.route("/api/ask", methods=["POST"])
@subscription_required
def api_ask():
    user = current_user()
    data = request.get_json() or {}
    q    = (data.get("question") or "").strip()
    if not q: return jsonify({"error":"No question provided"}), 400
    # WL-03: pass this user's watchlist into NLQ so their assets are prioritised
    wl = parse_watchlist(user.get("watchlist") or "")
    return jsonify({"answer":ask_orion(q, user["profile"], watchlist_items=wl),"question":q})


@app.route("/api/settings", methods=["POST"])
@login_required
def api_settings():
    user         = current_user()
    data         = request.get_json() or {}
    name         = (data.get("name") or user["name"]).strip()
    profile      = data.get("profile", user["profile"])
    email_digest = bool(data.get("email_digest", user["email_digest"]))
    digest_time  = data.get("digest_time", user["digest_time"])
    # WL-01: read watchlist — comma or newline separated, normalised in update_user_settings
    watchlist    = data.get("watchlist", user.get("watchlist") or "")
    if profile not in PROFILES: return jsonify({"error":"Invalid profile"}), 400
    update_user_settings(user["id"], name, profile, email_digest, digest_time, watchlist)
    # Return normalised watchlist so the UI can immediately reflect dedup/trim
    saved    = get_user_by_id(user["id"])
    wl_items = parse_watchlist(saved["watchlist"] if saved else "")
    return jsonify({"ok":True, "message":"Settings saved",
                    "watchlist_saved": wl_items, "watchlist_count": len(wl_items)})


@app.route("/api/test-email", methods=["POST"])
@login_required
def api_test_email():
    user=current_user(); ok,msg=test_smtp_connection()
    if not ok: return jsonify({"ok":False,"message":msg})
    subject=f"ORION Brief — SMTP Test ({datetime.now(IST).strftime('%H:%M IST')})"
    html=f"""<!DOCTYPE html><html><body style='background:#05070b;font-family:Georgia,serif;padding:32px'>
<div style='max-width:500px;margin:0 auto'>
  <p style='font-family:Arial,sans-serif;font-size:22px;letter-spacing:4px;color:#e8f2f8;font-weight:700'>ORION</p>
  <div style='background:#080d12;border-left:3px solid #22c55e;padding:20px;margin-top:16px'>
    <p style='font-family:monospace;font-size:9px;color:#22c55e;letter-spacing:1px;margin:0 0 8px'>✓ SMTP TEST SUCCESSFUL</p>
    <p style='color:#b8d0e0;font-size:14px;margin:0'>Email delivery configured correctly. Morning digests will arrive at 06:00 IST.</p>
  </div>
</div></body></html>"""
    sent=send_email(user["email"],subject,html,user_id=user["id"],email_type="test")
    return jsonify({"ok":sent,"message":f"Test email sent to {user['email']}" if sent else "SMTP connected but send failed"})


@app.route("/api/digest-status")
@login_required
def api_digest_status():
    user=current_user(); last=get_last_digest_status(user["id"])
    if not last: return jsonify({"status":"never_sent","message":"No digest sent yet"})
    return jsonify({"status":"delivered" if last["delivered"] else "failed","sent_at":last["sent_at"],
                    "subject":last["subject"],"delivered":bool(last["delivered"]),"error":last["error_msg"]})


@app.route("/api/rules", methods=["GET"])
@login_required
def api_get_rules():
    return jsonify({"rules":[dict(r) for r in get_user_rules(current_user()["id"])]})


@app.route("/api/rules", methods=["POST"])
@login_required
def api_create_rule():
    user=current_user(); data=request.get_json() or {}
    name=(data.get("name") or "").strip(); field=data.get("field","place")
    operator=data.get("operator","contains"); value=(data.get("value") or "").strip()
    if not name or not value: return jsonify({"error":"Name and value required"}), 400
    if field not in ["place","title","score","type","source"]: return jsonify({"error":"Invalid field"}), 400
    if operator not in ["contains","not_contains","gte","lte","equals"]: return jsonify({"error":"Invalid operator"}), 400
    create_rule(user["id"],name,field,operator,value)
    return jsonify({"ok":True,"message":f"Rule '{name}' created"})


@app.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
@login_required
def api_toggle_rule(rule_id): toggle_rule(rule_id,current_user()["id"]); return jsonify({"ok":True})


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@login_required
def api_delete_rule(rule_id): delete_rule(rule_id,current_user()["id"]); return jsonify({"ok":True})


@app.route("/api/alert-log")
@login_required
def api_alert_log():
    return jsonify({"logs":[dict(l) for l in get_user_alert_log(current_user()["id"])]})


# ─────────────────────────────────────────────────────────────────────
# SCHEDULER
# ─────────────────────────────────────────────────────────────────────

def _morning_job():
    print("⏰ 06:00 IST — morning refresh")
    load_all_data(); generate_all_briefs(); send_morning_digests()
    print("✓ Morning job complete")

scheduler = BackgroundScheduler(timezone="Asia/Kolkata", daemon=True)
scheduler.add_job(_morning_job, "cron", hour=6, minute=0, id="morning", replace_existing=True)
scheduler.start()
atexit.register(lambda: scheduler.shutdown(wait=False))


# ─────────────────────────────────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────────────────────────────────

def _startup():
    init_db()
    lock = Path(__file__).parent / ".startup.lock"
    if lock.exists() and (time.time()-lock.stat().st_mtime) < 90:
        _load_briefs_from_disk(); return
    lock.touch()
    print("\n╔══════════════════════════════════════════╗")
    print("║  ORION Brief v5  —  Python / Flask       ║")
    print("║  Recurring · Invoices · ACLED · NewsAPI  ║")
    print("╚══════════════════════════════════════════╝")
    print(f"{'✓' if ANTHROPIC_KEY else '⚠'}  API key: {'set' if ANTHROPIC_KEY else 'MISSING — demo mode'}")
    ok,msg = test_smtp_connection()
    print(f"{'✓' if ok else '⚠'}  SMTP: {msg if ok else msg}")
    print(f"{'✓' if RAZORPAY_KEY_ID else '⚠'}  Razorpay: {'configured' if RAZORPAY_KEY_ID else 'not set — demo payment mode'}")
    print(f"{'✓' if ACLED_API_KEY else '·'}  ACLED: {'configured' if ACLED_API_KEY else 'not set — skipped (optional)'}")
    print(f"{'✓' if NEWSAPI_KEY else '·'}  NewsAPI: {'configured' if NEWSAPI_KEY else 'not set — skipped (optional)'}")
    print(f"{'✓' if ADMIN_EMAIL else '⚠'}  Admin: {ADMIN_EMAIL or 'ADMIN_EMAIL not set in .env'}")
    print(f"✓  Base URL: {BASE_URL}")
    _load_briefs_from_disk()
    def _bg():
        try: load_all_data(); generate_all_briefs(); print(f"✓  Ready → {BASE_URL}")
        except Exception as e: print(f"Init error: {e}")
        finally: lock.unlink(missing_ok=True)
    threading.Thread(target=_bg, daemon=True).start()

_startup()

if __name__ == "__main__":
    print(f"\n→  {BASE_URL}\n")
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
