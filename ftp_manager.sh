#!/data/data/com.termux/files/usr/bin/bash
# FTP服务器管理脚本
# 文件名：ftp_manager.sh

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置路径
CONFIG_DIR="$HOME/.ftp_config"
USERS_FILE="$CONFIG_DIR/users.json"
LOG_DIR="$HOME/ftp_logs"
INSTALL_LOG="$LOG_DIR/install.log"
FTP_ROOT="$HOME/ftp_share"

# 显示横幅
show_banner() {
    clear
    echo -e "${GREEN}"
    echo "========================================"
    echo "    Termux FTP 服务器管理工具"
    echo "========================================"
    echo -e "${NC}"
}

# 显示菜单
show_menu() {
    echo ""
    echo -e "${BLUE}请选择操作:${NC}"
    echo "1. 安装FTP服务器"
    echo "2. 启动FTP服务器"
    echo "3. 停止FTP服务器"
    echo "4. 添加FTP用户"
    echo "5. 删除FTP用户"
    echo "6. 修改用户密码"
    echo "7. 查看所有用户"
    echo "8. 查看服务器状态"
    echo "9. 查看访问日志"
    echo "10. 备份用户数据"
    echo "0. 退出"
    echo ""
    echo -n "请输入选择 [0-10]: "
}

# 记录日志
log() {
    local message="$1"
    local level="${2:-INFO}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" | tee -a "$INSTALL_LOG"
}

# 检查并创建目录
check_dirs() {
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$FTP_ROOT"
    mkdir -p "$HOME/bin"
}

# 安装依赖 - 简化版
install_dependencies() {
    log "开始安装依赖包..."
    
    # 更新包列表
    pkg update -y && pkg upgrade -y
    
    # 安装必要软件
    pkg install -y python python-pip openssl nano wget curl
    
    # 安装Python FTP库
    pip install pyftpdlib
    
    log "依赖安装完成"
}

# 创建FTP服务器脚本 - 简化版
create_ftp_server_script() {
    cat > "$HOME/ftp_server.py" << 'EOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FTP服务器主程序 - 简化版
"""

import os
import sys
import json
import hashlib
import logging
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# 配置路径
BASE_DIR = os.path.expanduser("~")
CONFIG_DIR = os.path.join(BASE_DIR, ".ftp_config")
USERS_FILE = os.path.join(CONFIG_DIR, "users.json")
LOG_FILE = os.path.join(BASE_DIR, "ftp_logs", "ftp_server.log")

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

def load_users():
    """加载用户配置"""
    if not os.path.exists(USERS_FILE):
        return {}
    
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            users = json.load(f)
        logging.info(f"加载了 {len(users)} 个用户")
        return users
    except Exception as e:
        logging.error(f"加载用户配置失败: {e}")
        return {}

def start_server():
    """启动FTP服务器"""
    print("启动FTP服务器...")
    
    # 创建授权器
    authorizer = DummyAuthorizer()
    
    # 加载用户
    users = load_users()
    
    if not users:
        print("警告: 没有配置任何用户")
        print("请先使用管理工具添加用户")
        return
    
    # 添加用户到授权器
    for username, user_info in users.items():
        try:
            home_dir = user_info['home_dir']
            password = user_info['password']
            permissions = user_info.get('permissions', 'elradfmw')
            
            # 确保目录存在
            os.makedirs(home_dir, exist_ok=True)
            
            # 添加用户
            authorizer.add_user(username, password, home_dir, perm=permissions)
            print(f"✓ 用户已添加: {username} -> {home_dir}")
            
            # 设置目录权限
            os.chmod(home_dir, 0o755)
            
        except Exception as e:
            print(f"✗ 添加用户 {username} 失败: {e}")
    
    # 配置处理器
    handler = FTPHandler
    handler.authorizer = authorizer
    handler.banner = "Termux FTP Server"
    
    # 设置被动端口范围
    handler.passive_ports = range(60000, 60100)
    
    # 其他设置
    handler.max_login_attempts = 3
    handler.timeout = 300
    
    # 创建服务器
    server = FTPServer(('0.0.0.0', 2121), handler)
    
    # 连接限制
    server.max_cons = 10
    server.max_cons_per_ip = 3
    
    # 启动服务器
    print("=" * 50)
    print("FTP服务器已启动!")
    print("端口: 2121")
    print(f"用户数量: {len(users)}")
    print("=" * 50)
    print("按 Ctrl+C 停止服务器")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务器停止")
    finally:
        server.close_all()

if __name__ == '__main__':
    # 检查配置文件目录
    if not os.path.exists(CONFIG_DIR):
        print("错误: 配置目录不存在，请先运行安装程序")
        sys.exit(1)
    
    start_server()
EOF
    
    chmod +x "$HOME/ftp_server.py"
    log "FTP服务器脚本创建完成"
}

# 创建用户管理脚本 - 简化版
create_user_manager_script() {
    cat > "$HOME/bin/ftp_user_manager.py" << 'EOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FTP用户管理工具 - 简化版
"""

import os
import sys
import json
import hashlib
import getpass
from datetime import datetime

# 配置路径
BASE_DIR = os.path.expanduser("~")
CONFIG_DIR = os.path.join(BASE_DIR, ".ftp_config")
USERS_FILE = os.path.join(CONFIG_DIR, "users.json")

# 确保目录存在
os.makedirs(CONFIG_DIR, exist_ok=True)

def hash_password(password):
    """密码哈希函数"""
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    """加载用户配置"""
    if not os.path.exists(USERS_FILE):
        return {}
    
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"错误: 加载用户配置失败 - {e}")
        return {}

def save_users(users):
    """保存用户配置"""
    try:
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
        
        print("用户配置已保存")
        return True
    except Exception as e:
        print(f"错误: 保存用户配置失败 - {e}")
        return False

def add_user(username, password, home_dir, permissions='elradfmw'):
    """添加用户"""
    users = load_users()
    
    if username in users:
        print(f"错误: 用户 '{username}' 已存在")
        return False
    
    # 创建用户目录
    full_path = os.path.expanduser(home_dir)
    os.makedirs(full_path, exist_ok=True)
    
    # 设置目录权限
    os.chmod(full_path, 0o755)
    
    # 密码哈希
    password_hash = hash_password(password)
    
    # 用户信息
    users[username] = {
        'password': password_hash,
        'home_dir': full_path,
        'permissions': permissions,
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    if save_users(users):
        print(f"✓ 成功添加用户: {username}")
        print(f"  目录: {full_path}")
        print(f"  权限: {permissions}")
        return True
    return False

def delete_user(username):
    """删除用户"""
    users = load_users()
    
    if username not in users:
        print(f"错误: 用户 '{username}' 不存在")
        return False
    
    # 确认删除
    confirm = input(f"确定要删除用户 '{username}' 吗？(y/N): ")
    if confirm.lower() != 'y':
        print("操作取消")
        return False
    
    del users[username]
    
    if save_users(users):
        print(f"用户 '{username}' 已删除")
        return True
    return False

def change_password(username, new_password):
    """修改密码"""
    users = load_users()
    
    if username not in users:
        print(f"错误: 用户 '{username}' 不存在")
        return False
    
    # 密码哈希
    password_hash = hash_password(new_password)
    
    users[username]['password'] = password_hash
    users[username]['password_changed_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if save_users(users):
        print(f"用户 '{username}' 密码已修改")
        return True
    return False

def list_users():
    """列出所有用户"""
    users = load_users()
    
    if not users:
        print("没有配置任何用户")
        return
    
    print(f"{'用户名':<15} {'目录':<30} {'权限':<10} {'创建时间':<20}")
    print("=" * 85)
    
    for username, info in users.items():
        home_dir = info['home_dir']
        permissions = info['permissions']
        created_at = info.get('created_at', '未知')
        
        print(f"{username:<15} {home_dir:<30} {permissions:<10} {created_at:<20}")

def interactive_add_user():
    """交互式添加用户"""
    print("=== 添加FTP用户 ===")
    
    username = input("用户名: ").strip()
    if not username:
        print("用户名不能为空")
        return False
    
    password = getpass.getpass("密码: ")
    if not password:
        print("密码不能为空")
        return False
    
    confirm_password = getpass.getpass("确认密码: ")
    if password != confirm_password:
        print("密码不匹配")
        return False
    
    default_dir = os.path.join(BASE_DIR, "ftp_share", username)
    home_dir = input(f"用户目录 [默认: {default_dir}]: ").strip()
    if not home_dir:
        home_dir = default_dir
    
    permissions = input("权限 (默认: elradfmw): ").strip()
    if not permissions:
        permissions = "elradfmw"
    
    return add_user(username, password, home_dir, permissions)

def backup_users():
    """备份用户数据"""
    backup_file = os.path.join(CONFIG_DIR, f"users_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    
    users = load_users()
    
    try:
        with open(backup_file, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
        
        print(f"用户数据已备份到: {backup_file}")
        return backup_file
    except Exception as e:
        print(f"备份失败: {e}")
        return None

def main():
    """主函数"""
    if len(sys.argv) == 1:
        print("FTP用户管理工具")
        print("用法:")
        print("  python ftp_user_manager.py add     - 添加用户")
        print("  python ftp_user_manager.py del     - 删除用户")
        print("  python ftp_user_manager.py passwd  - 修改密码")
        print("  python ftp_user_manager.py list    - 列出用户")
        print("  python ftp_user_manager.py backup  - 备份用户数据")
        print("  python ftp_user_manager.py interactive - 交互式添加用户")
        return
    
    command = sys.argv[1]
    
    if command == 'add':
        if len(sys.argv) < 5:
            print("用法: python ftp_user_manager.py add 用户名 密码 目录")
            return
        add_user(sys.argv[2], sys.argv[3], sys.argv[4])
    
    elif command == 'del':
        if len(sys.argv) < 3:
            print("用法: python ftp_user_manager.py del 用户名")
            return
        delete_user(sys.argv[2])
    
    elif comman
