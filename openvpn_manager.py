import socket
import re
import os
import json
import subprocess
import shutil
from datetime import datetime, timedelta
from config import (
    OPENVPN_MGMT_HOST,
    OPENVPN_MGMT_PORT,
    OPENVPN_MGMT_TIMEOUT,
    OPENVPN_STATUS_LOG,
    EASYRSA_DIR,
    EASYRSA_KEYS_DIR,
    CLIENT_OUTPUT_DIR,
    CRL_FILE,
    SERVER_CONF,
    CA_CERT,
    INDEX_TXT,
    GEN_SCRIPT,
    GEN_OUTSIDE_SCRIPT,
    BACKUP_DIR,
    DEL_DIR,
    USER_STATE_FILE,
    OPENVPN_DIR,
)


class OpenVPNManager:
    """Interface to OpenVPN management console and certificate management."""

    def __init__(self):
        self._mgmt = None

    def _connect_mgmt(self):
        """Connect to OpenVPN management interface."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(OPENVPN_MGMT_TIMEOUT)
        sock.connect((OPENVPN_MGMT_HOST, OPENVPN_MGMT_PORT))
        sock.recv(4096)
        return sock

    def _send_mgmt_cmd(self, cmd):
        """Send command to management interface and return response."""
        try:
            sock = self._connect_mgmt()
            sock.sendall((cmd + "\n").encode())
            time_module = __import__("time")
            time_module.sleep(0.2)
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"END" in chunk or b"SUCCESS" in chunk or b"ERROR" in chunk:
                        break
                except socket.timeout:
                    break
            sock.close()
            return response.decode("utf-8", errors="replace")
        except (socket.error, ConnectionRefusedError):
            return None

    def get_status(self):
        """Get full OpenVPN status including connected clients."""
        resp = self._send_mgmt_cmd("status 2")
        if resp is None:
            return self._parse_status_log()

        clients = []
        in_client_list = False
        in_routing_table = False
        is_mgmt_format = "HEADER,CLIENT_LIST" in resp

        for line in resp.split("\n"):
            line = line.strip()

            if "CLIENT_LIST" in line and "Common Name" in line:
                in_client_list = True
                in_routing_table = False
                continue
            if "ROUTING_TABLE" in line:
                in_routing_table = True
                in_client_list = False
                continue
            if "GLOBAL" in line and ("STATS" in line or "STATS" in line):
                in_routing_table = False
                in_client_list = False
                continue

            if in_client_list and line and not line.startswith("OpenVPN"):
                # Mgmt interface prefix: CLIENT_LIST,
                if line.startswith("CLIENT_LIST,"):
                    line = line[len("CLIENT_LIST,"):]
                parts = line.split(",")
                if is_mgmt_format:
                    # Fields: cn, real, virt, virt6, rx, tx, since, ...
                    if len(parts) >= 7:
                        clients.append({
                            "common_name": parts[0].strip(),
                            "real_address": parts[1].strip(),
                            "bytes_received": int(parts[4].strip() or 0),
                            "bytes_sent": int(parts[5].strip() or 0),
                            "connected_since": parts[6].strip(),
                        })
                else:
                    # Fields: cn, real, rx, tx, since
                    if len(parts) >= 5:
                        clients.append({
                            "common_name": parts[0].strip(),
                            "real_address": parts[1].strip(),
                            "bytes_received": int(parts[2].strip() or 0),
                            "bytes_sent": int(parts[3].strip() or 0),
                            "connected_since": parts[4].strip(),
                        })

        return {"clients": clients, "raw": resp}

    def _parse_status_log(self):
        """Fallback: parse status log file."""
        clients = []
        if not os.path.exists(OPENVPN_STATUS_LOG):
            return {"clients": clients, "raw": ""}

        with open(OPENVPN_STATUS_LOG, "r") as f:
            raw = f.read()

        in_client_list = False
        for line in raw.split("\n"):
            if line.startswith("Common Name"):
                in_client_list = True
                continue
            if line.startswith("ROUTING TABLE") or line.startswith("GLOBAL STATS"):
                in_client_list = False
                continue
            if in_client_list and line.strip():
                parts = line.split(",")
                if len(parts) >= 5:
                    clients.append(
                        {
                            "common_name": parts[0].strip(),
                            "real_address": parts[1].strip().split(":")[0],
                            "bytes_received": int(parts[2].strip()),
                            "bytes_sent": int(parts[3].strip()),
                            "connected_since": parts[4].strip(),
                        }
                    )

        return {"clients": clients, "raw": raw}

    def get_load_stats(self):
        """Get global traffic stats from management interface."""
        resp = self._send_mgmt_cmd("load-stats")
        if resp is None:
            return {"nclients": 0, "bytesin": 0, "bytesout": 0}

        match = re.search(
            r"nclients=(\d+),bytesin=(\d+),bytesout=(\d+)", resp
        )
        if match:
            return {
                "nclients": int(match.group(1)),
                "bytesin": int(match.group(2)),
                "bytesout": int(match.group(3)),
            }
        return {"nclients": 0, "bytesin": 0, "bytesout": 0}

    def kill_client(self, common_name):
        """Disconnect a specific client."""
        return self._send_mgmt_cmd(f"kill {common_name}")

    # ─── Certificate Management ───────────────────────────────

    def get_all_users(self):
        """Get all certificate users and their state."""
        keys_dir = EASYRSA_KEYS_DIR
        users = []

        if not os.path.exists(keys_dir):
            return users

        user_states = self._load_user_states()
        revoked_set = self._get_revoked_certs()
        serial_pattern = re.compile(r"^[0-9A-F]+\.pem$")

        for fname in sorted(os.listdir(keys_dir)):
            if not fname.endswith(".crt"):
                continue
            # Skip serial-number named certs (old easy-rsa)
            if serial_pattern.match(fname.replace(".crt", ".pem")):
                continue

            username = fname[:-4]
            cert_path = os.path.join(keys_dir, fname)
            key_path = os.path.join(keys_dir, f"{username}.key")

            expire_info = self._get_cert_expiry(cert_path)
            has_key = os.path.exists(key_path)
            is_revoked = username in revoked_set or not has_key or user_states.get(username, {}).get("revoked", False)

            users.append(
                {
                    "username": username,
                    "cert_file": fname,
                    "expires": expire_info.get("expires", "Unknown"),
                    "expires_ts": expire_info.get("expires_ts", None),
                    "days_left": expire_info.get("days_left", None),
                    "revoked": is_revoked,
                    "ovpn_exists": os.path.exists(
                        os.path.join(CLIENT_OUTPUT_DIR, f"{username}.ovpn")
                    ),
                }
            )

        return users

    def _get_revoked_certs(self):
        """Parse index.txt for revoked certificates (old easy-rsa)."""
        revoked = set()
        if not os.path.exists(INDEX_TXT):
            return revoked
        with open(INDEX_TXT, "r") as f:
            for line in f:
                if line.startswith("R\t"):
                    m = re.search(r"/CN=([^/]+)", line)
                    if m:
                        revoked.add(m.group(1))
        return revoked

    def cleanup_expired(self):
        """Move expired (0d) user certs, keys, and ovpn to del dir."""
        import logging
        _log = logging.getLogger("openvpn-web")
        keys_dir = EASYRSA_KEYS_DIR
        del_dir = DEL_DIR

        if not os.path.exists(keys_dir):
            return

        os.makedirs(del_dir, exist_ok=True)
        moved = []
        serial_pattern = re.compile(r"^[0-9A-F]+\.pem$")

        for fname in sorted(os.listdir(keys_dir)):
            if not fname.endswith(".crt"):
                continue
            if serial_pattern.match(fname.replace(".crt", ".pem")):
                continue

            username = fname[:-4]
            cert_path = os.path.join(keys_dir, fname)
            expire_info = self._get_cert_expiry(cert_path)
            days_left = expire_info.get("days_left")

            if days_left is not None and days_left <= 0:
                for ext in [".crt", ".key", ".csr"]:
                    src = os.path.join(keys_dir, f"{username}{ext}")
                    if os.path.exists(src):
                        shutil.move(src, os.path.join(del_dir, f"{username}{ext}"))
                ovpn_path = os.path.join(CLIENT_OUTPUT_DIR, f"{username}.ovpn")
                if os.path.exists(ovpn_path):
                    shutil.move(ovpn_path, os.path.join(del_dir, f"{username}.ovpn"))
                # Disconnect if online
                self.kill_client(username)
                # Mark revoked in state
                self._update_user_state(username, expired=True)
                moved.append(username)
                _log.info("Cleaned up expired: %s", username)

        if moved:
            self._reload_openvpn()
        return moved
        with open(INDEX_TXT, "r") as f:
            for line in f:
                if line.startswith("R\t"):
                    m = re.search(r"/CN=([^/]+)", line)
                    if m:
                        revoked.add(m.group(1))
        return revoked

    def _get_cert_expiry(self, cert_path):
        """Extract certificate expiration date using openssl."""
        try:
            result = subprocess.run(
                ["openssl", "x509", "-enddate", "-noout", "-in", cert_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=10,
            )
            if result.returncode == 0:
                match = re.search(r"notAfter=(.+)", result.stdout)
                if match:
                    date_str = match.group(1).strip()
                    expires = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expires - datetime.now()).days
                    return {
                        "expires": expires.strftime("%Y-%m-%d %H:%M:%S"),
                        "expires_ts": expires.timestamp(),
                        "days_left": max(0, days_left),
                    }
        except Exception:
            pass
        return {"expires": "Unknown", "expires_ts": None, "days_left": None}

    def generate_client(self, username, days=365, password=None):
        """Generate a new client certificate and .ovpn file.

        Uses external script if configured, otherwise calls easy-rsa directly.
        """
        if GEN_SCRIPT and os.path.exists(GEN_SCRIPT):
            return self._generate_via_script(username, days)

        return self._generate_via_easyrsa(username, days, password)

    def generate_client_outside(self, username, days=365, ou="OUTER"):
        """Generate a client using the OUTSIDE/OUTER script with custom OU."""
        import logging
        _log = logging.getLogger("openvpn-web")

        if not GEN_OUTSIDE_SCRIPT or not os.path.exists(GEN_OUTSIDE_SCRIPT):
            return {"success": False, "message": "Outside generation script not configured"}

        try:
            self._sanitize_index()

            _log.info("Running outside script: %s %s %s %s", GEN_OUTSIDE_SCRIPT, username, days, ou)
            result = subprocess.run(
                ["bash", GEN_OUTSIDE_SCRIPT, username, str(days), ou],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=120,
            )
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            _log.info("Outside script exit: %s", result.returncode)
            if stdout:
                _log.info("Outside script stdout: %s", stdout[-500:])
            if stderr:
                _log.warning("Outside script stderr: %s", stderr[-500:])

            search_dirs = [
                CLIENT_OUTPUT_DIR,
                os.path.dirname(GEN_OUTSIDE_SCRIPT),
                os.path.join(os.path.dirname(GEN_OUTSIDE_SCRIPT), "client"),
                "/etc/openvpn/client",
                "/etc/openvpn/scripts/client",
                os.path.join(EASYRSA_DIR, "keys"),
            ]
            for d in search_dirs:
                for ext in [".ovpn", ".tar.gz", ".zip"]:
                    path = os.path.join(d, f"{username}{ext}")
                    if os.path.exists(path):
                        _log.info("Found outside output: %s", path)
                        self._sanitize_index()
                        return {
                            "success": True,
                            "username": username,
                            "ovpn_path": path,
                            "message": f"Outside client generated. Valid for {days} days.",
                        }

            return {
                "success": False,
                "message": f"Outside script completed (exit={result.returncode}) but .ovpn not found.",
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "message": "Outside generation timed out."}
        except Exception as e:
            _log.exception("Outside script error")
            return {"success": False, "message": str(e)}

    def _generate_via_script(self, username, days):
        """Call the existing shell script to generate client."""
        import logging
        _log = logging.getLogger("openvpn-web")

        try:
            # Clean dirty index entries BEFORE running gen script,
            # otherwise pkitool fails mid-way
            self._sanitize_index()

            _log.info("Running script: %s %s %s", GEN_SCRIPT, username, days)
            result = subprocess.run(
                ["bash", GEN_SCRIPT, username, str(days)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=120,
            )
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            _log.info("Script stdout: %s", stdout[-500:] if stdout else "(empty)")
            if stderr:
                _log.warning("Script stderr: %s", stderr[-500:])
            _log.info("Script exit code: %s", result.returncode)

            search_dirs = [
                CLIENT_OUTPUT_DIR,
                os.path.dirname(GEN_SCRIPT),
                os.path.join(os.path.dirname(GEN_SCRIPT), "client"),
                "/etc/openvpn/client",
                "/etc/openvpn/scripts/client",
                os.path.join(EASYRSA_DIR, "keys"),
            ]
            for d in search_dirs:
                for ext in [".ovpn", ".tar.gz", ".zip"]:
                    path = os.path.join(d, f"{username}{ext}")
                    if os.path.exists(path):
                        _log.info("Found output at: %s", path)
                        self._sanitize_index()
                        return {
                            "success": True,
                            "username": username,
                            "ovpn_path": path,
                            "message": "Client generated successfully via script.",
                        }

            return {
                "success": False,
                "message": f"Script completed (exit={result.returncode}) but .ovpn not found in: {', '.join(search_dirs)}. stdout: {stdout[-300:]}",
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "message": "Generation script timed out."}
        except Exception as e:
            _log.exception("Script execution error")
            return {"success": False, "message": str(e)}

    def _generate_via_easyrsa(self, username, days, password=None):
        """Generate client cert directly using easy-rsa."""
        easyrsa = os.path.join(EASYRSA_DIR, "easyrsa")

        if not os.path.exists(easyrsa):
            return {"success": False, "message": f"easyrsa not found at {easyrsa}"}

        nopass_flag = "nopass" if not password else ""

        try:
            cmd = [easyrsa, "--days", str(days), "build-client-full", username]
            if nopass_flag:
                cmd.append(nopass_flag)

            env = os.environ.copy()
            if password:
                env["EASYRSA_PASSIN"] = f"pass:{password}"
                env["EASYRSA_PASSOUT"] = f"pass:{password}"

            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=120,
                cwd=EASYRSA_DIR,
                env=env,
                input="yes\n" if password else None,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "message": f"easyrsa failed: {result.stderr}",
                }

            ovpn_path = self._build_ovpn_file(username)
            if ovpn_path:
                return {
                    "success": True,
                    "username": username,
                    "ovpn_path": ovpn_path,
                    "message": f"Client generated successfully. Valid for {days} days.",
                }
            return {"success": False, "message": "Cert generated but .ovpn build failed."}

        except subprocess.TimeoutExpired:
            return {"success": False, "message": "Certificate generation timed out."}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def _build_ovpn_file(self, username):
        """Build .ovpn file from template and certificate files."""
        ca_path = os.path.join(EASYRSA_DIR, "pki", "ca.crt")
        cert_path = os.path.join(EASYRSA_DIR, "pki", "issued", f"{username}.crt")
        key_path = os.path.join(EASYRSA_DIR, "pki", "private", f"{username}.key")
        ta_path = os.path.join(OPENVPN_DIR, "ta.key")

        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            return None

        template = OVPN_TEMPLATE
        if not os.path.exists(template):
            ovpn_lines = ["client", "dev tun", "proto udp"]
            try:
                with open(SERVER_CONF, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("remote "):
                            ovpn_lines.append(line)
                            break
            except Exception:
                ovpn_lines.append("remote YOUR_SERVER_IP 1194")

            ovpn_lines.extend(
                [
                    "resolv-retry infinite",
                    "nobind",
                    "persist-key",
                    "persist-tun",
                    "remote-cert-tls server",
                    "cipher AES-256-GCM",
                    "verb 3",
                ]
            )
        else:
            with open(template, "r") as f:
                ovpn_lines = f.read().strip().split("\n")

        with open(ca_path, "r") as f:
            ca_cert = f.read()
        with open(cert_path, "r") as f:
            client_cert = f.read()
        with open(key_path, "r") as f:
            client_key = f.read()

        ovpn_lines.append("\n<ca>")
        ovpn_lines.append(ca_cert.strip())
        ovpn_lines.append("</ca>")
        ovpn_lines.append("<cert>")
        ovpn_lines.append(client_cert.strip())
        ovpn_lines.append("</cert>")
        ovpn_lines.append("<key>")
        ovpn_lines.append(client_key.strip())
        ovpn_lines.append("</key>")

        if os.path.exists(ta_path):
            with open(ta_path, "r") as f:
                ta_content = f.read()
            ovpn_lines.append("key-direction 1")
            ovpn_lines.append("<tls-auth>")
            ovpn_lines.append(ta_content.strip())
            ovpn_lines.append("</tls-auth>")

        os.makedirs(CLIENT_OUTPUT_DIR, exist_ok=True)
        ovpn_path = os.path.join(CLIENT_OUTPUT_DIR, f"{username}.ovpn")
        with open(ovpn_path, "w") as f:
            f.write("\n".join(ovpn_lines))

        return ovpn_path

    # ─── Revoke / Restore ─────────────────────────────────────

    def _get_openssl_config(self):
        """Find the openssl config file used by old easy-rsa 2.x."""
        candidates = [
            os.path.join(EASYRSA_DIR, "openssl.cnf"),
            os.path.join(EASYRSA_DIR, "openssl-1.0.cnf"),
            os.path.join(EASYRSA_DIR, "openssl-1.0.0.cnf"),
        ]
        for c in candidates:
            if os.path.exists(c):
                return c

        vars_file = os.path.join(EASYRSA_DIR, "vars")
        if os.path.exists(vars_file):
            with open(vars_file, "r") as f:
                for line in f:
                    m = re.search(r'KEY_CONFIG\s*=\s*"?([^"\n]+)"?', line)
                    if m:
                        cfg = m.group(1).strip()
                        cfg = os.path.expandvars(cfg)
                        if not os.path.isabs(cfg):
                            cfg = os.path.join(EASYRSA_DIR, cfg)
                        if os.path.exists(cfg):
                            return cfg
        return os.path.join(EASYRSA_DIR, "openssl.cnf")

    def _source_vars_env(self):
        """Parse easy-rsa vars file and return environment dict with KEY_* variables set."""
        env = os.environ.copy()
        vars_file = os.path.join(EASYRSA_DIR, "vars")
        if not os.path.exists(vars_file):
            return env

        with open(vars_file, "r") as f:
            for line in f:
                line = line.strip()
                # Match uncommented: export KEY_FOO=value  or  KEY_FOO=value
                if line.startswith("#"):
                    continue
                m = re.match(r'(?:export\s+)?(KEY_\w+)\s*=\s*"?([^"\n]*)"?', line)
                if m:
                    key, val = m.group(1), m.group(2)
                    env[key] = val

        # Ensure all vars referenced in openssl.cnf have values
        for var in ["KEY_CN", "KEY_NAME", "KEY_OU", "KEY_ORG", "KEY_CITY",
                     "KEY_PROVINCE", "KEY_COUNTRY", "KEY_EMAIL", "KEY_SIZE"]:
            if var not in env:
                env[var] = "default"
        return env

    def _sanitize_index(self):
        """Clean index.txt: for V (valid) entries, clear revocation date (col 3).

        Old easy-rsa 2.x pkitool sometimes writes the issue date into the
        revocation date field, which confuses openssl ca -revoke when it scans
        the entire index.
        """
        import logging
        _log = logging.getLogger("openvpn-web")

        if not os.path.exists(INDEX_TXT):
            return
        lines = []
        changed = 0
        with open(INDEX_TXT, "r") as f:
            for line in f:
                if line.startswith("V\t"):
                    parts = line.split("\t")
                    if len(parts) >= 4 and parts[2].strip():
                        parts[2] = ""
                        line = "\t".join(parts)
                        changed += 1
                lines.append(line)
        if changed:
            with open(INDEX_TXT, "w") as f:
                f.writelines(lines)
            _log.info("Sanitized index.txt: cleared %d dirty V entries", changed)

    def revoke_user(self, username):
        """Revoke a user's certificate using old easy-rsa 2.x (openssl ca)."""
        import logging
        _log = logging.getLogger("openvpn-web")

        self._sanitize_index()

        keys_dir = EASYRSA_KEYS_DIR
        cert_file = os.path.join(keys_dir, f"{username}.crt")

        if not os.path.exists(cert_file):
            return {"success": False, "message": f"Certificate for '{username}' not found."}

        # Check if already revoked
        if username in self._get_revoked_certs():
            return {"success": False, "message": f"User '{username}' is already revoked."}

        # Backup cert and key
        backup_user_dir = os.path.join(BACKUP_DIR, username)
        os.makedirs(backup_user_dir, exist_ok=True)
        for fname in [f"{username}.crt", f"{username}.key", f"{username}.csr"]:
            src = os.path.join(keys_dir, fname)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(backup_user_dir, fname))

        cert_info = self._get_cert_expiry(cert_file)
        backup_info = {
            "username": username,
            "revoked_at": datetime.now().isoformat(),
            "cert_info": cert_info,
        }
        with open(os.path.join(backup_user_dir, "info.json"), "w") as f:
            json.dump(backup_info, f, indent=2)

        ssl_cfg = self._get_openssl_config()
        _log.info("Revoke using openssl config: %s", ssl_cfg)

        try:
            # Source vars before openssl (old easy-rsa 2.x requires env vars)
            defaults = 'KEY_CN=default KEY_NAME=default KEY_OU=default KEY_ORG=default KEY_CITY=default KEY_PROVINCE=default KEY_COUNTRY=default KEY_EMAIL=default KEY_ALTNAMES="" KEY_SIZE=2048 KEY_DIR=/tmp'
            cmd = (
                f'export {defaults}; '
                f'cd "{EASYRSA_DIR}" && source ./vars && '
                f'openssl ca -config "{ssl_cfg}" -revoke "{cert_file}"'
            )
            result = subprocess.run(
                ["bash", "-c", cmd],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=30,
            )
            if result.returncode != 0:
                _log.error("Revoke failed: %s", result.stderr)
                return {"success": False, "message": f"Revoke failed: {result.stderr}"}

            # Generate new CRL
            crl_out = os.path.join(keys_dir, "crl.pem")
            defaults = 'KEY_CN=default KEY_NAME=default KEY_OU=default KEY_ORG=default KEY_CITY=default KEY_PROVINCE=default KEY_COUNTRY=default KEY_EMAIL=default KEY_ALTNAMES="" KEY_SIZE=2048 KEY_DIR=/tmp'
            cmd = (
                f'export {defaults}; '
                f'cd "{EASYRSA_DIR}" && source ./vars && '
                f'openssl ca -config "{ssl_cfg}" -gencrl -out "{crl_out}"'
            )
            result = subprocess.run(
                ["bash", "-c", cmd],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=30,
            )
            if result.returncode != 0:
                _log.warning("CRL generation warning: %s", result.stderr)

            # Copy CRL to OpenVPN dir if needed
            if CRL_FILE != crl_out and os.path.exists(crl_out):
                shutil.copy2(crl_out, CRL_FILE)

            self._update_user_state(username, revoked=True)
            self._reload_openvpn()
            self.kill_client(username)

            _log.info("User '%s' revoked successfully", username)
            return {"success": True, "message": f"User '{username}' revoked successfully."}

        except Exception as e:
            _log.exception("Revoke error")
            return {"success": False, "message": str(e)}

    def restore_user(self, username, new_days=None):
        """Restore a revoked user by editing index.txt and regenerating CRL."""
        import logging
        _log = logging.getLogger("openvpn-web")

        # Method: Edit index.txt to change 'R' back to 'V' and regenerate CRL
        backup_user_dir = os.path.join(BACKUP_DIR, username)
        info_file = os.path.join(backup_user_dir, "info.json")

        if not os.path.exists(info_file):
            return {"success": False, "message": f"No backup found for '{username}'. Cannot restore."}

        with open(info_file, "r") as f:
            backup_info = json.load(f)

        old_cert_info = backup_info.get("cert_info", {})
        if new_days is None and old_cert_info.get("days_left") is not None:
            new_days = max(30, old_cert_info["days_left"])
        if new_days is None:
            new_days = 365

        keys_dir = EASYRSA_KEYS_DIR

        # Restore backup files
        for fname in [f"{username}.crt", f"{username}.key", f"{username}.csr"]:
            backup_file = os.path.join(backup_user_dir, fname)
            if os.path.exists(backup_file):
                shutil.copy2(backup_file, os.path.join(keys_dir, fname))

        # Edit index.txt: change "R\t..." back to "V\t..." for this user
        try:
            index_path = INDEX_TXT
            if os.path.exists(index_path):
                lines = []
                with open(index_path, "r") as f:
                    for line in f:
                        if f"/CN={username}" in line and line.startswith("R\t"):
                            line = "V" + line[1:]
                            _log.info("Restored index entry for '%s'", username)
                        lines.append(line)
                with open(index_path, "w") as f:
                    f.writelines(lines)
                _log.info("Updated %s", index_path)
        except Exception as e:
            _log.warning("Failed to update index.txt: %s", e)

        # Regenerate CRL
        self._sanitize_index()
        ssl_cfg = self._get_openssl_config()
        crl_out = os.path.join(keys_dir, "crl.pem")
        defaults = 'KEY_CN=default KEY_NAME=default KEY_OU=default KEY_ORG=default KEY_CITY=default KEY_PROVINCE=default KEY_COUNTRY=default KEY_EMAIL=default KEY_ALTNAMES="" KEY_SIZE=2048 KEY_DIR=/tmp'
        cmd = (
            f'export {defaults}; '
            f'cd "{EASYRSA_DIR}" && source ./vars && '
            f'openssl ca -config "{ssl_cfg}" -gencrl -out "{crl_out}"'
        )
        subprocess.run(
            ["bash", "-c", cmd],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=30,
        )
        if CRL_FILE != crl_out and os.path.exists(crl_out):
            shutil.copy2(crl_out, CRL_FILE)

        self._update_user_state(username, revoked=False)
        self._reload_openvpn()

        return {
            "success": True,
            "message": f"User '{username}' restored. Valid for {new_days} days.",
            "ovpn_path": os.path.join(CLIENT_OUTPUT_DIR, f"{username}.ovpn"),
        }

    def _reload_openvpn(self):
        """No reload needed. OpenVPN re-reads CRL on each new TLS handshake.
        Revoked users are immediately disconnected via management interface.
        The updated CRL file blocks reconnection without disturbing others.
        """
        pass

    def _load_user_states(self):
        """Load user states from JSON file."""
        if os.path.exists(USER_STATE_FILE):
            try:
                with open(USER_STATE_FILE, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {}

    def _update_user_state(self, username, **kwargs):
        """Update state for a specific user."""
        states = self._load_user_states()
        if username not in states:
            states[username] = {}
        states[username].update(kwargs)
        states[username]["updated_at"] = datetime.now().isoformat()
        os.makedirs(os.path.dirname(USER_STATE_FILE) or OPENVPN_DIR, exist_ok=True)
        with open(USER_STATE_FILE, "w") as f:
            json.dump(states, f, indent=2)

    def get_user_ovpn_path(self, username):
        """Get path to user's .ovpn file."""
        ovpn_path = os.path.join(CLIENT_OUTPUT_DIR, f"{username}.ovpn")
        if os.path.exists(ovpn_path):
            return ovpn_path
        return None

    def get_traffic_summary(self):
        """Get combined traffic summary: global stats + per-user traffic."""
        load_stats = self.get_load_stats()
        status = self.get_status()

        total_rx = load_stats.get("bytesin", 0)
        total_tx = load_stats.get("bytesout", 0)

        user_traffic = []
        for client in status.get("clients", []):
            user_traffic.append(
                {
                    "username": client["common_name"],
                    "ip": client["real_address"],
                    "rx": client["bytes_received"],
                    "tx": client["bytes_sent"],
                    "rx_human": self._format_bytes(client["bytes_received"]),
                    "tx_human": self._format_bytes(client["bytes_sent"]),
                    "connected_since": client["connected_since"],
                }
            )

        return {
            "total_rx": total_rx,
            "total_tx": total_tx,
            "total_rx_human": self._format_bytes(total_rx),
            "total_tx_human": self._format_bytes(total_tx),
            "active_connections": len(user_traffic),
            "users": user_traffic,
        }

    @staticmethod
    def _format_bytes(n):
        """Format bytes to human-readable string."""
        if n is None:
            n = 0
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if n < 1024:
                return f"{n:.2f} {unit}"
            n /= 1024
        return f"{n:.2f} PB"
