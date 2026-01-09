#!/data/data/com.termux/files/usr/bin/bash
# 文件名：simple_ftp_setup.sh

echo "正在安装FTP服务器..."

# 更新和安装
pkg update -y && pkg upgrade -y
pkg install -y python python-pip openssl

# 安装Python库
pip install pyftpdlib

# 创建配置目录
mkdir -p ~/.ftp_config
mkdir -p ~/ftp_share
mkdir -p ~/ftp_logs

# 创建用户管理脚本
cat > ~/ftp_admin.py << 'EOF'
#!/usr/bin/env python3
import os
import json
import hashlib
import sys

CONFIG_FILE = os.path.expanduser("~/.ftp_config/users.json")

def load_users():
    if not os.path.exists(CONFIG_FILE):
        return {}
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def add_user(username, password, directory):
    users = load_users()
    
    if username in users:
        print(f"错误: 用户 '{username}' 已存在")
        return False
    
    # 创建目录
    os.makedirs(directory, exist_ok=True)
    
    # 哈希密码
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    # 保存用户
    users[username] = {
        'password': password_hash,
        'directory': directory,
        'permissions': 'elradfmw'
    }
    
    save_users(users)
    print(f"用户 '{username}' 添加成功！")
    print(f"目录: {directory}")
    return True

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("用法: python ftp_admin.py 用户名 密码 目录")
        sys.exit(1)
    
    add_user(sys.argv[1], sys.argv[2], sys.argv[3])
EOF

chmod +x ~/ftp_admin.py

# 创建启动脚本
cat > ~/start_ftp_simple.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash

echo "启动FTP服务器..."
cd ~
python -c "
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import os
import json

# 加载用户
config_file = os.path.expanduser('~/.ftp_config/users.json')
users = {}
if os.path.exists(config_file):
    with open(config_file, 'r') as f:
        users = json.load(f)

# 创建授权器
authorizer = DummyAuthorizer()

# 添加用户
for username, info in users.items():
    directory = info['directory']
    password = info['password']
    os.makedirs(directory, exist_ok=True)
    authorizer.add_user(username, password, directory, perm='elradfmw')

# 配置处理器
handler = FTPHandler
handler.authorizer = authorizer
handler.banner = 'Simple FTP Server'

# 创建服务器
server = FTPServer(('0.0.0.0', 2121), handler)

print('FTP服务器启动在端口 2121')
print(f'已加载 {len(users)} 个用户')

server.serve_forever()
"
EOF

chmod +x ~/start_ftp_simple.sh

echo "安装完成！"
echo ""
echo "使用方法:"
echo "1. 添加用户: python ~/ftp_admin.py 用户名 密码 目录"
echo "2. 启动服务器: bash ~/start_ftp_simple.sh"
echo ""
echo "示例:"
echo "  python ~/ftp_admin.py user1 password123 ~/ftp_share/user1"
echo "  python ~/ftp_admin.py user2 password456 ~/ftp_share/user2"
echo "  bash ~/start_ftp_simple.sh"
