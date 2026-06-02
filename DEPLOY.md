# OpenVPN Web Manager - Deployment Guide

## Requirements

- Ubuntu 18.04+ with Python 3.6+
- OpenVPN installed and running
- easy-rsa 2.x configured at `/etc/openvpn/easy-rsa/`
- OpenVPN management interface enabled

## 1. Upload

```bash
scp -r openvpn-web/ root@your-server:/proj/tools/openvpn-web
```

## 2. Install Dependencies

```bash
cd /proj/tools/openvpn-web
pip3 install -r requirements.txt
# If pip3 not installed: apt install -y python3-pip
```

## 3. Configuration

Edit `config.py`:

```python
# --- Required ---

# OpenVPN Management Interface
OPENVPN_MGMT_HOST = "127.0.0.1"
OPENVPN_MGMT_PORT = 7505

# Paths (adjust for your setup)
EASYRSA_DIR = "/etc/openvpn/easy-rsa"
EASYRSA_KEYS_DIR = "/etc/openvpn/easy-rsa/keys"
CLIENT_OUTPUT_DIR = "/etc/openvpn/scripts/ovpns"
CRL_FILE = "/etc/openvpn/crl.pem"
INDEX_TXT = "/etc/openvpn/easy-rsa/keys/index.txt"

# Generation scripts
GEN_SCRIPT = "/etc/openvpn/scripts/gen-iclab.sh"         # Internal clients
GEN_OUTSIDE_SCRIPT = "/etc/openvpn/scripts/gen-outser.sh" # Outside/OUTER clients

# Admin credentials (CHANGE THESE)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "your-secure-password"

# --- Optional: SMTP for emailing .ovpn files ---
SMTP_HOST = "smtp.example.com"
SMTP_PORT = 465
SMTP_USE_SSL = True
SMTP_USERNAME = "vpn@example.com"
SMTP_PASSWORD = "your-password"
SMTP_FROM = "vpn@example.com"
SMTP_FROM_NAME = "OpenVPN Admin"
```

## 4. Enable OpenVPN Management Interface

Add to `/etc/openvpn/server.conf`:

```
management 127.0.0.1 7505
```

Then restart OpenVPN:

```bash
systemctl restart openvpn@server
# or: systemctl restart openvpn
```

Verify:

```bash
echo "status 2" | nc -w 2 127.0.0.1 7505 | head -20
```

## 5. Install Service

```bash
cp /proj/tools/openvpn-web/openvpn-web.service /etc/systemd/system/
# Edit the service file if needed (WorkingDirectory, ExecStart paths)
systemctl daemon-reload
systemctl enable openvpn-web
systemctl start openvpn-web
```

## 6. Access

```
http://your-server-ip:5000
```

## Features

| Feature | Description |
|---------|-------------|
| **Dashboard** | Total traffic RX/TX, active connections count |
| **Traffic per user** | Per-client bytes received/sent, connection duration |
| **Generate client** | Create .ovpn with specified validity (days), using internal gen script |
| **Generate outside client** | Create .ovpn with custom OU field, using outside gen script |
| **Download .ovpn** | Download generated config file |
| **Email .ovpn** | Send config file as email attachment (requires SMTP config) |
| **Revoke** | Revoke certificate via CRL, immediately disconnect user |
| **Restore** | Remove certificate from CRL, allow reconnection |
| **Disconnect** | Force-disconnect a single client |
| **Auto cleanup** | Move expired (0-day) certs to `/etc/openvpn/del/` |
| **Sorting** | Users sorted: Online > Offline > Revoked |

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/traffic` | GET | Global + per-user RX/TX stats |
| `/api/users` | GET | All users with status and traffic |
| `/api/users/generate` | POST | Generate internal client `{username, days}` |
| `/api/users/generate-outside` | POST | Generate outside client `{username, days, ou}` |
| `/api/users/<name>/download` | GET | Download .ovpn file |
| `/api/users/<name>/email` | POST | Email .ovpn file `{email}` |
| `/api/users/<name>/revoke` | POST | Revoke certificate |
| `/api/users/<name>/restore` | POST | Restore certificate `{days}` |
| `/api/users/<name>/kill` | POST | Disconnect client |

## Nginx Reverse Proxy (Recommended)

```nginx
server {
    listen 80;
    server_name vpn.example.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Security Notes

- Change admin password in `config.py` before use
- Use firewall rules to restrict access (iptables / ufw)
- Use Nginx + Let's Encrypt for HTTPS
- The web app runs as root (needed for easy-rsa operations)
- `crl-verify /etc/openvpn/crl.pem` must be in `server.conf` for revocation to work

## Troubleshooting

```bash
# View logs
journalctl -u openvpn-web -f

# Check OpenVPN management interface
echo "status 2" | nc -w 2 127.0.0.1 7505

# Verify CRL
openssl crl -in /etc/openvpn/crl.pem -text -noout | head

# Clean dirty index entries (V with revocation date)
python3 -c "
lines = []
with open('/etc/openvpn/easy-rsa/keys/index.txt') as f:
    for line in f:
        if line.startswith('V\t'):
            p = line.split('\t')
            if len(p) >= 4 and p[2].strip():
                p[2] = ''
                line = '\t'.join(p)
        lines.append(line)
with open('/etc/openvpn/easy-rsa/keys/index.txt', 'w') as f:
    f.writelines(lines)
print('done')
"
```
