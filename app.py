import os
import sys
import json
import re
import logging
import traceback
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from functools import wraps
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file,
    session,
    redirect,
    url_for,
)
from config import (
    ADMIN_USERNAME, ADMIN_PASSWORD, FLASK_HOST, FLASK_PORT, SECRET_KEY,
    SMTP_HOST, SMTP_PORT, SMTP_USE_SSL, SMTP_USERNAME, SMTP_PASSWORD,
    SMTP_FROM, SMTP_FROM_NAME,
)
from openvpn_manager import OpenVPNManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("openvpn-web")

app = Flask(__name__)
app.secret_key = SECRET_KEY or os.urandom(24)
ovpn = OpenVPNManager()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)

    return decorated


# ─── Auth Routes ────────────────────────────────────────────


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        data = request.get_json() if request.is_json else request.form
        username = data.get("username", "")
        password = data.get("password", "")
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["logged_in"] = True
            return jsonify({"success": True})
        return jsonify({"success": False, "message": "Invalid credentials"}), 401
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login_page"))


# ─── Page Routes ────────────────────────────────────────────


@app.route("/")
@login_required
def index():
    return render_template("index.html")


# ─── API Routes ─────────────────────────────────────────────


@app.route("/api/traffic")
@login_required
def api_traffic():
    """Get traffic summary: total + per-user."""
    try:
        summary = ovpn.get_traffic_summary()
        return jsonify({"success": True, "data": summary})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/users")
@login_required
def api_users():
    """Get all registered users with their status."""
    try:
        ovpn.cleanup_expired()
        all_users = ovpn.get_all_users()
        traffic = ovpn.get_traffic_summary()

        online_map = {}
        for u in traffic.get("users", []):
            online_map[u["username"]] = u

        for user in all_users:
            uname = user["username"]
            if uname in online_map:
                user["online"] = True
                user["rx"] = online_map[uname]["rx"]
                user["tx"] = online_map[uname]["tx"]
                user["rx_human"] = online_map[uname]["rx_human"]
                user["tx_human"] = online_map[uname]["tx_human"]
                user["connected_since"] = online_map[uname]["connected_since"]
                user["ip"] = online_map[uname]["ip"]
                del online_map[uname]
            else:
                user["online"] = False
                user["rx"] = 0
                user["tx"] = 0
                user["rx_human"] = "0 B"
                user["tx_human"] = "0 B"
                user["connected_since"] = None
                user["ip"] = None

        for uname, u in online_map.items():
            all_users.append({
                "username": uname,
                "cert_file": None,
                "expires": None,
                "expires_ts": None,
                "days_left": None,
                "revoked": False,
                "ovpn_exists": False,
                "online": True,
                "rx": u["rx"],
                "tx": u["tx"],
                "rx_human": u["rx_human"],
                "tx_human": u["tx_human"],
                "connected_since": u["connected_since"],
                "ip": u["ip"],
                "no_cert": True,
            })

        # Sort: Online first, then Offline, then Revoked
        def sort_key(u):
            if u.get("online"):
                return (0, u["username"])
            if u.get("revoked"):
                return (2, u["username"])
            return (1, u["username"])
        all_users.sort(key=sort_key)

        return jsonify({"success": True, "data": all_users})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/users/generate", methods=["POST"])
@login_required
def api_generate_user():
    """Generate a new client certificate and .ovpn file."""
    data = request.get_json()
    username = (data.get("username") or "").strip()
    days = data.get("days", 365)
    password = data.get("password")

    if not username:
        return jsonify({"success": False, "message": "Username is required"}), 400

    if not username.isalnum():
        return (
            jsonify(
                {"success": False, "message": "Username must be alphanumeric"}
            ),
            400,
        )

    try:
        days = int(days)
        if days < 1 or days > 3650:
            return (
                jsonify(
                    {"success": False, "message": "Days must be between 1 and 3650"}
                ),
                400,
            )
    except (ValueError, TypeError):
        return jsonify({"success": False, "message": "Invalid days value"}), 400

    try:
        result = ovpn.generate_client(username, days, password)
        if result.get("success"):
            logger.info("User '%s' generated successfully", username)
            return jsonify(result)
        logger.error("Generate user '%s' failed: %s", username, result.get("message", "unknown"))
        return jsonify(result), 500
    except Exception as e:
        logger.error("Generate user '%s' exception: %s\n%s", username, str(e), traceback.format_exc())
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/users/generate-outside", methods=["POST"])
@login_required
def api_generate_outside():
    """Generate a client using the OUTSIDE/OUTER script."""
    data = request.get_json()
    username = (data.get("username") or "").strip()
    days = data.get("days", 365)
    ou = (data.get("ou") or "OUTER").strip()

    if not username:
        return jsonify({"success": False, "message": "Username is required"}), 400

    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return jsonify({"success": False, "message": "Username must be alphanumeric"}), 400

    try:
        days = int(days)
        if days < 1 or days > 3650:
            return jsonify({"success": False, "message": "Days must be between 1 and 3650"}), 400
    except (ValueError, TypeError):
        return jsonify({"success": False, "message": "Invalid days value"}), 400

    try:
        result = ovpn.generate_client_outside(username, days, ou)
        if result.get("success"):
            logger.info("Outside user '%s' generated", username)
            return jsonify(result)
        logger.error("Outside generate '%s' failed: %s", username, result.get("message", "unknown"))
        return jsonify(result), 500
    except Exception as e:
        logger.error("Outside generate '%s' exception: %s", username, str(e))
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/users/<username>/revoke", methods=["POST"])
@login_required
def api_revoke_user(username):
    """Revoke a user's certificate."""
    result = ovpn.revoke_user(username)
    if result.get("success"):
        return jsonify(result)
    return jsonify(result), 500


@app.route("/api/users/<username>/restore", methods=["POST"])
@login_required
def api_restore_user(username):
    """Restore a revoked user's certificate."""
    data = request.get_json() or {}
    new_days = data.get("days")
    if new_days is not None:
        try:
            new_days = int(new_days)
        except (ValueError, TypeError):
            return jsonify({"success": False, "message": "Invalid days value"}), 400

    result = ovpn.restore_user(username, new_days)
    if result.get("success"):
        return jsonify(result)
    return jsonify(result), 500


@app.route("/api/users/<username>/download")
@login_required
def api_download_ovpn(username):
    """Download .ovpn file for a user."""
    ovpn_path = ovpn.get_user_ovpn_path(username)
    if ovpn_path and os.path.exists(ovpn_path):
        return send_file(
            ovpn_path,
            as_attachment=True,
            download_name=f"{username}.ovpn",
            mimetype="application/x-openvpn-profile",
        )
    return jsonify({"success": False, "message": ".ovpn file not found"}), 404


@app.route("/api/users/<username>/email", methods=["POST"])
@login_required
def api_email_ovpn(username):
    """Send .ovpn file to user via email."""
    data = request.get_json() or {}
    recipient = (data.get("email") or "").strip()

    if not recipient:
        return jsonify({"success": False, "message": "Email address is required"}), 400

    ovpn_path = ovpn.get_user_ovpn_path(username)
    if not ovpn_path or not os.path.exists(ovpn_path):
        return jsonify({"success": False, "message": ".ovpn file not found"}), 404

    try:
        msg = MIMEMultipart()
        msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM}>"
        msg["To"] = recipient
        msg["Subject"] = f"OpenVPN Configuration - {username}"

        body = f"""Hello {username},

Your OpenVPN configuration file is attached.

Username: {username}

Please import the attached .ovpn file into your OpenVPN client.

--
OpenVPN Admin
"""
        msg.attach(MIMEText(body, "plain"))

        with open(ovpn_path, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f'attachment; filename="{username}.ovpn"',
            )
            msg.attach(part)

        context = ssl.create_default_context()
        if SMTP_USE_SSL:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=15)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15)
            server.starttls(context=context)

        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_FROM, [recipient], msg.as_string())
        server.quit()

        logger.info("OVPN sent to %s for user %s", recipient, username)
        return jsonify({"success": True, "message": f"Configuration sent to {recipient}"})

    except Exception as e:
        logger.error("Email failed: %s", str(e))
        return jsonify({"success": False, "message": f"Failed to send email: {str(e)}"}), 500


@app.route("/api/users/<username>/kill", methods=["POST"])
@login_required
def api_kill_user(username):
    """Disconnect a connected client."""
    resp = ovpn.kill_client(username)
    if resp and "SUCCESS" in resp:
        return jsonify({"success": True, "message": f"User '{username}' disconnected."})
    return (
        jsonify(
            {
                "success": False,
                "message": f"Failed to disconnect '{username}'. User may not be connected.",
            }
        ),
        500,
    )


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    return render_template("index.html"), 404


if __name__ == "__main__":
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False)
