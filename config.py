# OpenVPN Web Manager Configuration
# Modify these paths to match your Ubuntu server setup

# OpenVPN Management Interface
OPENVPN_MGMT_HOST = "127.0.0.1"
OPENVPN_MGMT_PORT = 7505
OPENVPN_MGMT_TIMEOUT = 5

# File paths
OPENVPN_STATUS_LOG = "/var/log/openvpn/openvpn-status.log"
OPENVPN_DIR = "/etc/openvpn"
EASYRSA_DIR = "/etc/openvpn/easy-rsa"
EASYRSA_KEYS_DIR = "/etc/openvpn/easy-rsa/keys"
CLIENT_OUTPUT_DIR = "/etc/openvpn/scripts/ovpns"
CRL_FILE = "/etc/openvpn/crl.pem"
SERVER_CONF = "/etc/openvpn/server.conf"
CA_CERT = "/etc/openvpn/easy-rsa/keys/ca.crt"
INDEX_TXT = "/etc/openvpn/easy-rsa/keys/index.txt"

# External script for generating .ovpn (internal)
GEN_SCRIPT = "/etc/openvpn/scripts/gen-iclab.sh"

# External script for generating .ovpn (outside/OUTER)
GEN_OUTSIDE_SCRIPT = "/etc/openvpn/scripts/gen-outser.sh"

# Certificate backup directory for revoke/restore
BACKUP_DIR = "/etc/openvpn/revoked-backup"

# Expired certificates move here
DEL_DIR = "/etc/openvpn/del"

# User state tracking
USER_STATE_FILE = "/etc/openvpn/user-states.json"

# Web admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# Flask config
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
FLASK_DEBUG = False
SECRET_KEY = "change-this-to-a-random-secret-key"

# SMTP mail config for sending .ovpn to users
SMTP_HOST = "smtp.example.com"
SMTP_PORT = 465
SMTP_USE_SSL = True
SMTP_USERNAME = "vpn@example.com"
SMTP_PASSWORD = "your-password"
SMTP_FROM = "vpn@example.com"
SMTP_FROM_NAME = "OpenVPN Admin"
