# OpenVPN Web Manager - 部署说明

## 环境要求

- Ubuntu 18.04 及以上，Python 3.6+
- OpenVPN 已安装运行
- easy-rsa 2.x 配置在 `/etc/openvpn/easy-rsa/`
- OpenVPN management interface 已开启

## 1. 上传文件

```bash
scp -r openvpn-web/ root@服务器IP:/proj/tools/openvpn-web
```

## 2. 安装依赖

```bash
cd /proj/tools/openvpn-web
pip3 install -r requirements.txt
# 如果没有 pip3：apt install -y python3-pip
```

## 3. 修改配置

编辑 `config.py`，至少修改以下内容：

```python
# --- 必改项 ---

# 管理员密码
ADMIN_PASSWORD = "你的强密码"

# SMTP 邮箱配置（可不填，不影响其他功能）
SMTP_HOST = "smtp.example.com"
SMTP_PORT = 465
SMTP_USERNAME = "vpn@example.com"
SMTP_PASSWORD = "邮箱密码"
SMTP_FROM = "vpn@example.com"

# --- 路径配置（按实际环境调整）---
EASYRSA_DIR = "/etc/openvpn/easy-rsa"
EASYRSA_KEYS_DIR = "/etc/openvpn/easy-rsa/keys"
CLIENT_OUTPUT_DIR = "/etc/openvpn/scripts/ovpns"
CRL_FILE = "/etc/openvpn/crl.pem"

# 生成脚本
GEN_SCRIPT = "/etc/openvpn/scripts/gen-iclab.sh"         # 内部用户
GEN_OUTSIDE_SCRIPT = "/etc/openvpn/scripts/gen-outser.sh" # 外部用户(OUTER)
```

## 4. 开启 OpenVPN Management Interface

在 `/etc/openvpn/server.conf` 中添加：

```
management 127.0.0.1 7505
```

重启 OpenVPN：

```bash
systemctl restart openvpn@server
# 或 systemctl restart openvpn
```

验证是否生效：

```bash
echo "status 2" | nc -w 2 127.0.0.1 7505 | head -20
```

## 5. 配置吊销验证

确认 `server.conf` 中有 CRL 配置：

```
crl-verify /etc/openvpn/crl.pem
```

如果没有，添加后重启 OpenVPN，吊销功能才能有效阻止用户重新连接。

## 6. 安装系统服务

```bash
# 编辑服务文件确认路径正确
cp /proj/tools/openvpn-web/openvpn-web.service /etc/systemd/system/

# 如需修改路径：
# sed -i 's|/opt/openvpn-web|/proj/tools/openvpn-web|g' /etc/systemd/system/openvpn-web.service

systemctl daemon-reload
systemctl enable openvpn-web
systemctl start openvpn-web
```

## 7. 访问

```
http://服务器IP:5000
```

默认账号：`admin` / `admin123`

## 功能说明

| 功能 | 说明 |
|------|------|
| **总流量统计** | OpenVPN 隧道内总收/发流量 |
| **用户流量** | 每个在线用户的实时收/发字节数 |
| **生成内部用户** | 使用 gen-iclab.sh 脚本，输入用户名和有效期(天) |
| **生成外部用户** | 使用 gen-outser.sh 脚本，用户名/天数/OU 均可配 |
| **下载 ovpn** | 下载用户的 .ovpn 配置文件 |
| **邮件发送** | 将 .ovpn 作为附件发送到用户邮箱 |
| **Revoke 吊销** | 吊销证书并立即断开连接，加入 CRL 黑名单，禁止重连 |
| **Restore 恢复** | 从 CRL 中移除，用户可用原证书重新连接 |
| **Disconnect 断开** | 强制踢掉某个在线用户（不吊销证书） |
| **过期清理** | Days Left = 0 的用户自动移到 `/etc/openvpn/del/` |
| **排序** | 用户列表按 在线 → 离线 → 已吊销 排序，每 30 秒自动刷新 |

## API 接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/traffic` | GET | 获取总流量和每用户流量 |
| `/api/users` | GET | 获取所有用户及状态 |
| `/api/users/generate` | POST | 生成内部用户 `{username, days}` |
| `/api/users/generate-outside` | POST | 生成外部用户 `{username, days, ou}` |
| `/api/users/<用户名>/download` | GET | 下载 ovpn 文件 |
| `/api/users/<用户名>/email` | POST | 发邮件 `{email}` |
| `/api/users/<用户名>/revoke` | POST | 吊销证书 |
| `/api/users/<用户名>/restore` | POST | 恢复证书 `{days}` |
| `/api/users/<用户名>/kill` | POST | 断开连接 |

## Revoke / Restore 工作原理

```
Revoke:
  清理 index.txt → openssl ca -revoke → openssl ca -gencrl
  → 生成新 CRL 覆盖 /etc/openvpn/crl.pem
  → 通过 management 接口单独踢掉该用户
  → 用户尝试重连时 OpenVPN 重新读取 CRL 文件，拒绝该证书

Restore:
  恢复备份文件 → 修改 index.txt (R→V) → 清理脏数据
  → openssl ca -gencrl → 生成新 CRL
  → 用户可用原 ovpn 重新连接

整个过程不发送 SIGHUP，不影响其他已连接用户。
```

## 安全建议

- 修改 `config.py` 中的管理员密码
- 用 Nginx 反代并配置 HTTPS
- 用 iptables/ufw 限制 5000 端口仅内网访问
- Web 服务以 root 运行（操作 easy-rsa 需要），注意访问控制

## Nginx 反代（推荐）

```nginx
server {
    listen 80;
    server_name vpn.你的域名.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 常见问题排查

```bash
# 查看 web 服务日志
journalctl -u openvpn-web -f

# 手动测试管理接口
echo "status 2" | nc -w 2 127.0.0.1 7505

# 查看 CRL 内容
openssl crl -in /etc/openvpn/crl.pem -text -noout | head

# 查看某个用户在 index.txt 中的状态
grep "用户名" /etc/openvpn/easy-rsa/keys/index.txt

# 清理 index.txt 脏数据（V 状态却有吊销日期的条目）
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
