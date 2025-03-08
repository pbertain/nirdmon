# Version: 9
__app_name__ = "Nirdmon"
__version__ = "9.0"
__author__ = "The Nird Club"
__license__ = "MIT"

from flask import Flask, render_template, request, redirect, url_for, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import mysql.connector
import threading
import time
import requests
import ssl
import smtplib
import dns.resolver
import os
import matplotlib.pyplot as plt
from dotenv import load_dotenv
from datetime import datetime
import OpenSSL

# Load environment variables
load_dotenv(dotenv_path="config/.env")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id, username, password, is_admin):
        self.id = id
        self.username = username
        self.password = password
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(user["id"], user["username"], user["password"], user["is_admin"])
    return None

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        autocommit=True  # Helps reduce lock wait issues
    )

@app.route("/")
def index():
    if not current_user.is_authenticated:
        return render_template("public.html")
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT domain, http_status, ssl_status, dns_status, smtp_status, last_checked FROM monitored_domains")
    domains = cursor.fetchall()
    conn.close()
    return render_template("index.html", domains=domains)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and bcrypt.check_password_hash(user["password"], password):
            user_obj = User(user["id"], user["username"], user["password"], user["is_admin"])
            login_user(user_obj)
            return redirect(url_for("index"))
        
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/add_domain", methods=["POST"])
@login_required
def add_domain():
    if not current_user.is_admin:
        return redirect(url_for("index"))
    domain = request.form.get("domain")
    if domain:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO monitored_domains (domain) VALUES (%s)", (domain,))
            conn.commit()
        except mysql.connector.IntegrityError:
            pass  # Ignore duplicate entries
        conn.close()
    return redirect(url_for("index"))

@app.route("/manage_users", methods=["GET", "POST"])
@login_required
def manage_users():
    if not current_user.is_admin:
        return redirect(url_for("index"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        is_admin = request.form.get("is_admin") == "on"

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        cursor.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (%s, %s, %s)",
            (username, hashed_password, is_admin),
        )
        conn.commit()

    cursor.execute("SELECT id, username, is_admin FROM users")
    users = cursor.fetchall()
    conn.close()

    return render_template("manage_users.html", users=users)

@app.route("/status_chart")
def status_chart():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT domain, http_status, ssl_status, dns_status, smtp_status FROM monitored_domains")
    data = cursor.fetchall()
    conn.close()

    fig, axes = plt.subplots(len(data), 1, figsize=(6, 4 * len(data)))  # One chart per domain

    if len(data) == 1:
        axes = [axes]  # Ensure iterable

    for i, row in enumerate(data):
        labels = ["HTTP", "SSL", "DNS", "SMTP"]
        values = [
            row["http_status"].count("OK"),
            row["ssl_status"].count("OK"),
            row["dns_status"].count("OK"),
            row["smtp_status"].count("OK"),
        ]
        axes[i].bar(labels, values, color=["green", "yellow", "red", "gray"])
        axes[i].set_title(f"Status for {row['domain']}")
        axes[i].set_ylim(0, 1)
        axes[i].grid(axis="y", linestyle="--")

    plt.tight_layout()
    chart_path = "static/status_chart.png"
    plt.savefig(chart_path)
    plt.close()

    return render_template("status_chart.html", chart_url=url_for("static", filename="status_chart.png"))

# Monitoring Functions
def monitor_domains():
    while True:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT domain FROM monitored_domains")
        domains = cursor.fetchall()

        for domain in domains:
            domain_name = domain["domain"]
            http_status = check_http(domain_name)
            ssl_status = check_ssl(domain_name)
            dns_status = check_dns(domain_name)
            smtp_status = check_smtp(domain_name)

            cursor.execute("""
                UPDATE monitored_domains 
                SET http_status = %s, ssl_status = %s, dns_status = %s, smtp_status = %s, last_checked = NOW() 
                WHERE domain = %s
            """, (http_status, ssl_status, dns_status, smtp_status, domain_name))
        
        conn.commit()
        conn.close()
        time.sleep(900)  # Run every 15 minutes

def check_http(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        return "OK" if response.status_code == 200 else "WARN" if response.status_code in [403, 404] else "ERROR"
    except:
        return "ERROR"

def check_ssl(domain):
    try:
        cert = ssl.get_server_certificate((domain, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        expiry_date = datetime.strptime(x509.get_notAfter().decode('utf-8'), "%Y%m%d%H%M%SZ")
        remaining_days = (expiry_date - datetime.utcnow()).days
        return "OK" if remaining_days > 30 else "WARN" if remaining_days > 7 else "ERROR"
    except:
        return "ERROR"

def check_dns(domain):
    try:
        answers = dns.resolver.resolve(domain, "A")
        return "OK" if answers else "ERROR"
    except dns.resolver.NXDOMAIN:
        return "WARN"
    except:
        return "ERROR"

def check_smtp(domain):
    try:
        server = smtplib.SMTP(f"mail.{domain}")
        server.quit()
        return "OK"
    except:
        return "ERROR"

# Start Monitoring in Background Thread
monitor_thread = threading.Thread(target=monitor_domains, daemon=True)
monitor_thread.start()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=54080)

