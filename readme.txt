openvpn-web.service中的以下配置
WorkingDirectory=/opt/openvpn-web
ExecStart=/usr/bin/python3 /opt/openvpn-web/app.py
要改为实际目录


支持生成iclab、outside的ovpn文件；
支持自定义时长；
支持下载生成的ovpn；
支持通过email发送ovpn给用户；
优化排序：online——offline——revoke；


2026.05.25=》当前目录下的openvpn_manager.py文件已经修复了revoke和restore时候会重启openvpn服务的问题。