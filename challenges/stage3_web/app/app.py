#!/usr/bin/env python3
"""
CyberBank: Broken Online Banking Portal (Stage 3 Challenge)

An intentionally vulnerable simulated corporate online banking portal.
Vulnerability Demonstration:
    - Insecure Direct Object Reference (IDOR / BOLA) on /account and /transactions
    - Server verifies user is logged in, but fails to authorize that the logged-in
      user owns the requested account_id parameter.
"""

import os
import sqlite3
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
app.secret_key = os.environ.get("SECRET_KEY", "cyberbank_stage3_super_secret_portal_key_2026")
DB_PATH = os.path.join(BASE_DIR, "banking.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# Ensure database exists when imported by WSGI servers like Gunicorn
if not os.path.exists(DB_PATH):
    pass  # Defined after init_db function


def init_db():
    """Initialize simulated banking database with fake customer and vault records."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'customer'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            account_id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            account_number TEXT NOT NULL,
            account_type TEXT NOT NULL,
            balance REAL NOT NULL,
            currency TEXT NOT NULL DEFAULT 'USD',
            status TEXT NOT NULL DEFAULT 'ACTIVE',
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            tx_code TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            description TEXT NOT NULL,
            amount REAL NOT NULL,
            tx_type TEXT NOT NULL,
            notes TEXT,
            FOREIGN KEY (account_id) REFERENCES accounts (account_id)
        )
    """)

    # Seed initial fake records
    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM accounts")
    cursor.execute("DELETE FROM transactions")

    # User 1: Executive Elena
    cursor.execute("""
        INSERT INTO users (id, username, password_hash, full_name, role)
        VALUES (1, 'e_rostova_exec', ?, 'Elena Rostova', 'executive')
    """, (generate_password_hash("ExecutiveVaultSecretKey99!"),))

    # User 2: Standard Testing Customer (Given to players)
    cursor.execute("""
        INSERT INTO users (id, username, password_hash, full_name, role)
        VALUES (2, 'customer_user', ?, 'Alice Smith', 'customer')
    """, (generate_password_hash("Password123!"),))

    # User 3: Customer Bob
    cursor.execute("""
        INSERT INTO users (id, username, password_hash, full_name, role)
        VALUES (3, 'bob_customer', ?, 'Bob Johnson', 'customer')
    """, (generate_password_hash("BobCustomerSecret88#"),))

    # Account 1001: Elena Rostova Personal Checking
    cursor.execute("""
        INSERT INTO accounts (account_id, user_id, account_number, account_type, balance, currency, status)
        VALUES (1001, 1, 'CB-CHK-1001', 'Executive Tier Checking', 1250000.00, 'USD', 'ACTIVE')
    """)

    # Account 1002: Alice Smith (Standard User)
    cursor.execute("""
        INSERT INTO accounts (account_id, user_id, account_number, account_type, balance, currency, status)
        VALUES (1002, 2, 'CB-SAV-1002', 'Standard Personal Savings', 4250.00, 'USD', 'ACTIVE')
    """)

    # Account 1003: Bob Johnson
    cursor.execute("""
        INSERT INTO accounts (account_id, user_id, account_number, account_type, balance, currency, status)
        VALUES (1003, 3, 'CB-CHK-1003', 'Standard Personal Checking', 8910.50, 'USD', 'ACTIVE')
    """)

    # Account 7721: BlackVault Reserve Master Account (IDOR Target)
    cursor.execute("""
        INSERT INTO accounts (account_id, user_id, account_number, account_type, balance, currency, status)
        VALUES (7721, 1, 'CB-VAULT-7721', 'BlackVault Master Liquidity Reserve', 942500000.00, 'USD', 'RESTRICTED')
    """)

    # Standard Transactions for Alice (1002)
    cursor.execute("""
        INSERT INTO transactions (account_id, tx_code, timestamp, description, amount, tx_type, notes)
        VALUES 
        (1002, 'TX-90112', '2026-07-16 14:20:00', 'Direct Deposit Payroll', 2500.00, 'CREDIT', 'CyberBank Monthly Salary'),
        (1002, 'TX-90113', '2026-07-17 09:12:00', 'ATM Cash Withdrawal - Sector 4', -200.00, 'DEBIT', 'Branch 04 ATM 2'),
        (1002, 'TX-90114', '2026-07-18 11:45:00', 'Utility Auto-Pay', -150.00, 'DEBIT', 'Metropolitan Grid Power')
    """)

    # Standard Transactions for Elena (1001)
    cursor.execute("""
        INSERT INTO transactions (account_id, tx_code, timestamp, description, amount, tx_type, notes)
        VALUES 
        (1001, 'TX-80441', '2026-07-15 10:00:00', 'Quarterly Executive Bonus', 250000.00, 'CREDIT', 'Executive Committee Allocation')
    """)

    # High-Value Confidential Transactions for BlackVault Reserve (7721) -> CONTAINS FLAG
    cursor.execute("""
        INSERT INTO transactions (account_id, tx_code, timestamp, description, amount, tx_type, notes)
        VALUES 
        (7721, 'TX-882018-BV', '2026-07-14 02:00:00', 'Interbank Federal Settlement', 50000000.00, 'CREDIT', 'FedWire Batch 88201'),
        (7721, 'TX-882019-BV', '2026-07-15 03:15:22', 'BlackVault Master Reserve Synchronization', 942500000.00, 'CREDIT', 'Clearance verification: CBANK{WEB_sqli_byp4ss_v4ult_7721}'),
        (7721, 'TX-882020-BV', '2026-07-16 04:30:10', 'Encrypted SWIFT Ingress Protocol', -12000000.00, 'DEBIT', 'Internal Ledger Settlement')
    """)

    conn.commit()
    conn.close()


# Ensure database tables and seed data exist on startup
if not os.path.exists(DB_PATH):
    init_db()


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]
            flash(f"Welcome back, {user['full_name']}.", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid banking credentials.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    # Fetch accounts owned by user
    accounts = conn.execute(
        "SELECT * FROM accounts WHERE user_id = ?", (session["user_id"],)
    ).fetchall()
    conn.close()

    return render_template("dashboard.html", accounts=accounts)


# =========================================================================
# VULNERABLE ENDPOINTS (IDOR / BOLA)
# The server checks if user is logged in, but uses the user-supplied
# account_id parameter directly without verifying account ownership.
# =========================================================================

@app.route("/account")
def account_view():
    if "user_id" not in session:
        return redirect(url_for("login"))

    account_id = request.args.get("account_id")
    if not account_id:
        # Fallback to default user account
        conn = get_db()
        first_acc = conn.execute(
            "SELECT account_id FROM accounts WHERE user_id = ?", (session["user_id"],)
        ).fetchone()
        conn.close()
        account_id = first_acc["account_id"] if first_acc else 1002

    conn = get_db()
    # IDOR Vulnerability: Queries by account_id without 'AND user_id = session["user_id"]'
    account = conn.execute(
        "SELECT a.*, u.full_name as owner_name FROM accounts a JOIN users u ON a.user_id = u.id WHERE a.account_id = ?",
        (account_id,)
    ).fetchone()
    conn.close()

    if not account:
        flash(f"Account ID #{account_id} not found.", "warning")
        return redirect(url_for("dashboard"))

    return render_template("account.html", account=account)


@app.route("/transactions")
def transactions_view():
    if "user_id" not in session:
        return redirect(url_for("login"))

    account_id = request.args.get("account_id")
    if not account_id:
        account_id = 1002

    conn = get_db()
    # IDOR Vulnerability: Fetching transactions for ANY requested account_id
    account = conn.execute(
        "SELECT a.*, u.full_name as owner_name FROM accounts a JOIN users u ON a.user_id = u.id WHERE a.account_id = ?",
        (account_id,)
    ).fetchone()

    transactions = conn.execute(
        "SELECT * FROM transactions WHERE account_id = ? ORDER BY id DESC",
        (account_id,)
    ).fetchall()
    conn.close()

    if not account:
        flash(f"Account #{account_id} does not exist.", "danger")
        return redirect(url_for("dashboard"))

    return render_template("transactions.html", account=account, transactions=transactions)


@app.route("/api/account/<int:account_id>")
def api_account(account_id: int):
    """API endpoint vulnerable to BOLA / IDOR."""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    account = conn.execute(
        "SELECT a.*, u.full_name as owner_name FROM accounts a JOIN users u ON a.user_id = u.id WHERE a.account_id = ?",
        (account_id,)
    ).fetchone()

    if not account:
        conn.close()
        return jsonify({"error": "Account not found"}), 404

    txs = conn.execute(
        "SELECT * FROM transactions WHERE account_id = ? ORDER BY id DESC",
        (account_id,)
    ).fetchall()
    conn.close()

    return jsonify({
        "account_id": account["account_id"],
        "account_number": account["account_number"],
        "account_type": account["account_type"],
        "owner_name": account["owner_name"],
        "balance": account["balance"],
        "status": account["status"],
        "transactions": [dict(t) for t in txs],
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "CyberBank Online Banking Portal v2.4"})


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
