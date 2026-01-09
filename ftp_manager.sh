#!/data/data/com.termux/files/usr/bin/bash
# FTP服务器综合管理脚本
# 文件名：ftp_manager.sh
# 版本: 3.0 - 支持Root优化和Shizuku兼容

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 配置路径
CONFIG_DIR="$HOME/.ftp_config"
USERS_FILE="$CONFIG_DIR/users.json"
LOG_DIR="$HOME/ftp_logs"
INSTALL_LOG="$LOG_DIR/install.log"
FTP_ROOT="$HOME/ftp_share"
SHIZUKU_SOCKET="shizuku"

# 检测权限状态
check_permissions() {
    local status="normal"
    
    # 检测root权限
    if [ "$(id -u)" = "0" ]; then
        status="root"
    elif [ -x "/system/bin/su" ] && su -c "echo root" 2>/dev/null | grep -q "root"; then
        status="su_root"
    elif command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
        status="sudo"
    # 检测Shizuku权限
    elif command -v shizuku &>/dev/null && shizuku -v 2>/dev/null; then
        status="shizuku"
    elif [ -S "/data/local/tmp/shizuku.sock" ] || [ -S "/data/adb/shizuku/shizuku.sock" ]; then
        status="shizuku"
    fi
    
    echo "$status"
}

# 执行特权命令
run_privileged() {
    local cmd="$1"
    local permission_status=$(check_permissions)
    
    case $permission_status in
        "root")
            su -c "$cmd"
            ;;
        "su_root")
            su -c "$cmd"
            ;;
        "sudo")
            sudo "$cmd"
            ;;
        "shizuku")
            if command -v shizuku &>/dev/null; then
                shizuku -e "$cmd"
            elif [ -S "/data/local/tmp/shizuku.sock" ]; then
                sh /data/local/tmp/shizuku_shell "$cmd"
            else
                echo -e "${RED}Shizuku权限执行失败${NC}"
                return 1
            fi
            ;;
        *)
            echo -e "${YELLOW}需要特权权限执行: $cmd${NC}"
            return 1
            ;;
    esac
}

# 显示横幅
show_banner() {
    clear
    echo -e "${GREEN}"
    echo "========================================"
    echo "    Termux FTP 服务器管理工具 v3.0"
    echo "========================================"
    
    # 显示权限状态
    PERM_STATUS=$(check_permissions)
    case $PERM_STATUS in
        "root"|"su_root")
            echo -e "${YELLOW}  🔒 检测到ROOT权限 - 已启用高级功能${NC}"
            ;;
        "sudo")
            echo -e "${CYAN}  ⚡ 检测到SUDO权限 - 部分功能可用${NC}"
            ;;
        "shizuku")
            echo -e "${PURPLE}  ⚡ 检测到Shizuku权限 - 部分功能可用${NC}"
            ;;
        *)
            echo -e "${BLUE}  👤 普通用户模式 - 基本功能可用${NC}"
            ;;
    esac
    
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
    echo "11. 恢复用户数据"
    echo "12. 卸载FTP服务器"
    echo "13. 生成连接二维码"
    echo "14. 配置SFTP模式"
    
    # 根据权限显示高级菜单
    PERM_STATUS=$(check_permissions)
    if [ "$PERM_STATUS" != "normal" ]; then
        echo "15. 高级设置 (Root/Shizuku)"
    fi
    
    echo "0. 退出"
    echo ""
    
    if [ "$PERM_STATUS" != "normal" ]; then
        echo -n "请输入选择 [0-15]: "
    else
        echo -n "请输入选择 [0-14]: "
    fi
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
    mkdir -p "$CONFIG_DIR/backups"
    
    # 创建用户数据目录
    mkdir -p "$FTP_ROOT/public"
    mkdir -p "$FTP_ROOT/private"
}

# 安装依赖
install_dependencies() {
    log "开始安装依赖包..."
    
    # 更新包列表
    pkg update -y && pkg upgrade -y
    
    # 安装必要软件
    pkg install -y python python-pip openssl nano wget curl \
                   termux-api libqrencode jq bc
    
    # 安装Python FTP库
    pip install pyftpdlib
    
    # 根据权限安装额外软件
    PERM_STATUS=$(check_permissions)
    if [ "$PERM_STATUS" != "normal" ]; then
        echo -e "${YELLOW}检测到特殊权限，是否安装额外工具？(y/N): ${NC}"
        read -r install_extra
        if [ "$install_extra" = "y" ] || [ "$install_extra" = "Y" ]; then
            log "安装额外工具..."
            pkg install -y nmap iptables tcpdump 2>/dev/null || log "某些包安装失败" "WARNING"
        fi
    fi
    
    log "依赖安装完成"
}

# 配置端口（根据权限优化）
configure_ports() {
    PERM_STATUS=$(check_permissions)
    DEFAULT_PORT=2121
    STANDARD_PORT=false
    
    # 如果有特殊权限，询问是否使用标准端口
    if [ "$PERM_STATUS" != "normal" ]; then
        echo ""
        echo -e "${YELLOW}检测到特殊权限，可以进行端口优化：${NC}"
        echo "1. 使用标准FTP端口(21) - 需要Root/Shizuku权限"
        echo "2. 使用标准SFTP端口(22) - 需要Root/Shizuku权限"
        echo "3. 使用自定义端口(2121) - 推荐"
        echo "4. 使用随机高端口(30000-40000)"
        echo -n "请选择端口配置 [1-4]: "
        read -r port_choice
        
        case $port_choice in
            1)
                if [ "$PERM_STATUS" = "root" ] || [ "$PERM_STATUS" = "su_root" ]; then
                    DEFAULT_PORT=21
                    STANDARD_PORT=true
                    echo -e "${GREEN}已选择标准FTP端口(21)${NC}"
                else
                    echo -e "${RED}标准FTP端口需要完全Root权限，使用自定义端口${NC}"
                fi
                ;;
            2)
                DEFAULT_PORT=22
                STANDARD_PORT=true
                echo -e "${GREEN}已选择标准SFTP端口(22)${NC}"
                ;;
            3)
                echo -e "${GREEN}使用自定义端口(2121)${NC}"
                ;;
            4)
                DEFAULT_PORT=$((RANDOM % 10000 + 30000))
                echo -e "${GREEN}使用随机端口($DEFAULT_PORT)${NC}"
                ;;
            *)
                echo -e "${YELLOW}使用默认端口(2121)${NC}"
                ;;
        esac
    fi
    
    echo "$DEFAULT_PORT"
}

# 创建FTP服务器脚本
create_ftp_server_script() {
    PORT=$(configure_ports)
    
    cat > "$HOME/ftp_server.py" << EOF
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FTP服务器主程序
支持多用户、不同目录、权限控制
"""

import os
import sys
import json
import hashlib
import logging
from datetime import datetime
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, ThrottledDTPHandler
from pyftpdlib.servers import FTPServer
import configparser
import signal

# 配置路径
BASE_DIR = os.path.expanduser("~")
CONFIG_DIR = os.path.join(BASE_DIR, ".ftp_config")
USERS_FILE = os.path.join(CONFIG_DIR, "users.json")
LOG_FILE = os.path.join(BASE_DIR, "ftp_logs", "ftp_server.log")

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_users():
    """加载用户配置"""
    if not os.path.exists(USERS_FILE):
        return {}
    
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            users = json.load(f)
        logger.info(f"加载了 {len(users)} 个用户")
        return users
    except Exception as e:
        logger.error(f"加载用户配置失败: {e}")
        return {}

def save_users(users):
    """保存用户配置"""
    try:
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
        logger.info("用户配置已保存")
    except Exception as e:
        logger.error(f"保存用户配置失败: {e}")

class CustomFTPHandler(FTPHandler):
    """自定义FTP处理器"""
    
    def on_connect(self):
        logger.info(f"新连接: {self.remote_ip}:{self.remote_port}")
    
    def on_login(self, username):
        logger.info(f"用户登录: {username} from {self.remote_ip}")
    
    def on_logout(self, username):
        logger.info(f"用户登出: {username}")
    
    def on_file_sent(self, file):
        logger.info(f"文件发送: {file}")
    
    def on_file_received(self, file):
        logger.info(f"文件接收: {file}")
    
    def on_incomplete_file_sent(self, file):
        logger.warning(f"文件发送未完成: {file}")
    
    def on_incomplete_file_received(self, file):
        logger.warning(f"文件接收未完成: {file}")

def start_server():
    """启动FTP服务器"""
    # 加载配置
    config = configparser.ConfigParser()
    config.read(os.path.join(CONFIG_DIR, 'server.conf'))
    
    # 服务器配置
    host = config.get('server', 'host', fallback='0.0.0.0')
    port = config.getint('server', 'port', fallback=${PORT})
    passive_ports_start = config.getint('server', 'passive_ports_start', fallback=60000)
    passive_ports_end = config.getint('server', 'passive_ports_end', fallback=60100)
    max_connections = config.getint('server', 'max_connections', fallback=10)
    max_connections_per_ip = config.getint('server', 'max_connections_per_ip', fallback=3)
    
    # 创建授权器
    authorizer = DummyAuthorizer()
    
    # 加载用户
    users = load_users()
    
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
            logger.info(f"用户已添加: {username} -> {home_dir}")
            
            # 设置目录权限
            os.chmod(home_dir, 0o755)
            
        except Exception as e:
            logger.error(f"添加用户 {username} 失败: {e}")
    
    # 设置匿名用户（可选）
    if config.getboolean('server', 'allow_anonymous', fallback=False):
        anonymous_dir = config.get('server', 'anonymous_dir', fallback=os.path.join(BASE_DIR, 'ftp_share', 'anonymous'))
        os.makedirs(anonymous_dir, exist_ok=True)
        authorizer.add_anonymous(anonymous_dir, perm='elr')
        logger.info(f"匿名访问已启用 -> {anonymous_dir}")
    
    # 配置处理器
    handler = CustomFTPHandler
    handler.authorizer = authorizer
    
    # 设置被动端口范围
    handler.passive_ports = range(passive_ports_start, passive_ports_end)
    
    # 设置带宽限制（可选）
    dtp_handler = ThrottledDTPHandler
    
    # 安全地获取下载限制
    try:
        dtp_handler.read_limit = config.getint('server', 'download_limit', fallback=102400)
    except (ValueError, configparser.NoOptionError, configparser.NoSectionError) as e:
        logger.warning(f"读取下载限制失败，使用默认值: {e}")
        dtp_handler.read_limit = 102400
    
    # 安全地获取上传限制
    try:
        dtp_handler.write_limit = config.getint('server', 'upload_limit', fallback=102400)
    except (ValueError, configparser.NoOptionError, configparser.NoSectionError) as e:
        logger.warning(f"读取上传限制失败，使用默认值: {e}")
        dtp_handler.write_limit = 102400
    
    handler.dtp_handler = dtp_handler
    
    # 其他设置
    handler.banner = config.get('server', 'banner', fallback="Termux FTP Server - Secure File Transfer")
    handler.max_login_attempts = 3
    
    # 安全地获取超时设置
    try:
        handler.timeout = config.getint('server', 'timeout', fallback=300)
    except (ValueError, configparser.NoOptionError, configparser.NoSectionError) as e:
        logger.warning(f"读取超时设置失败，使用默认值: {e}")
        handler.timeout = 300
    
    # 创建服务器
    server = FTPServer((host, port), handler)
    
    # 连接限制
    server.max_cons = max_connections
    server.max_cons_per_ip = max_connections_per_ip
    
    # 信号处理
    def signal_handler(signum, frame):
        logger.info("收到关闭信号，正在停止服务器...")
        server.close_all()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 启动服务器
    logger.info(f"FTP服务器启动在 {host}:{port}")
    logger.info(f"被动端口范围: {passive_ports_start}-{passive_ports_end}")
    logger.info(f"最大连接数: {max_connections}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("服务器被用户中断")
    finally:
        server.close_all()

if __name__ == '__main__':
    # 检查配置文件目录
    if not os.path.exists(CONFIG_DIR):
        print("错误: 配置目录不存在，请先运行安装程序")
        sys.exit(1)
    
    print("启动FTP服务器...")
    start_server()
EOF
    
    chmod +x "$HOME/ftp_server.py"
    log "FTP服务器脚本创建完成"
}

# 创建用户管理脚本
create_user_manager_script() {
    cat > "$HOME/bin/ftp_user_manager.py" << 'EOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FTP用户管理工具
"""

import os
import sys
import json
import hashlib
import getpass
import argparse
from datetime import datetime

# 配置路径
BASE_DIR = os.path.expanduser("~")
CONFIG_DIR = os.path.join(BASE_DIR, ".ftp_config")
USERS_FILE = os.path.join(CONFIG_DIR, "users.json")
BACKUP_DIR = os.path.join(CONFIG_DIR, "backups")

# 确保目录存在
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)

def hash_password(password, method='sha256'):
    """密码哈希函数"""
    if method == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif method == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    else:
        return password  # 不加密（不推荐）

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
        # 创建备份
        backup_file = os.path.join(BACKUP_DIR, f"users_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(backup_file, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2)
        
        # 保存新配置
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
        
        print(f"用户配置已保存，备份在: {backup_file}")
        return True
    except Exception as e:
        print(f"错误: 保存用户配置失败 - {e}")
        return False

def add_user(username, password, home_dir, permissions='elradfmw', quota_mb=0, encrypt=True):
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
    
    # 密码处理
    if encrypt:
        password_hash = hash_password(password)
    else:
        password_hash = password
    
    # 用户信息
    users[username] = {
        'password': password_hash,
        'home_dir': full_path,
        'permissions': permissions,
        'quota_mb': quota_mb,
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'last_login': None,
        'encrypted': encrypt
    }
    
    if save_users(users):
        print(f"成功添加用户: {username}")
        print(f"  目录: {full_path}")
        print(f"  权限: {permissions}")
        print(f"  配额: {quota_mb} MB")
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
    
    # 密码处理
    if users[username].get('encrypted', True):
        password_hash = hash_password(new_password)
    else:
        password_hash = new_password
    
    users[username]['password'] = password_hash
    users[username]['password_changed_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if save_users(users):
        print(f"用户 '{username}' 密码已修改")
        return True
    return False

def list_users(show_passwords=False):
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
        
        # 显示密码（仅用于调试）
        password_display = ""
        if show_passwords:
            password_display = f"密码: {info['password'][:10]}..." if len(info['password']) > 10 else f"密码: {info['password']}"
        
        print(f"{username:<15} {home_dir:<30} {permissions:<10} {created_at:<20} {password_display}")

def backup_users():
    """备份用户数据"""
    backup_file = os.path.join(BACKUP_DIR, f"users_full_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    
    users = load_users()
    
    # 包含额外的元数据
    backup_data = {
        'backup_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_users': len(users),
        'users': users
    }
    
    try:
        with open(backup_file, 'w', encoding='utf-8') as f:
            json.dump(backup_data, f, indent=2, ensure_ascii=False)
        
        print(f"用户数据已备份到: {backup_file}")
        return backup_file
    except Exception as e:
        print(f"备份失败: {e}")
        return None

def restore_users(backup_file):
    """恢复用户数据"""
    if not os.path.exists(backup_file):
        print(f"错误: 备份文件不存在 - {backup_file}")
        return False
    
    try:
        with open(backup_file, 'r', encoding='utf-8') as f:
            backup_data = json.load(f)
        
        users = backup_data.get('users', {})
        
        # 确认恢复
        print(f"备份信息:")
        print(f"  备份时间: {backup_data.get('backup_time', '未知')}")
        print(f"  用户数量: {len(users)}")
        
        confirm = input("确定要恢复这个备份吗？(y/N): ")
        if confirm.lower() != 'y':
            print("操作取消")
            return False
        
        # 保存恢复的用户
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
        
        print("用户数据已恢复")
        return True
    except Exception as e:
        print(f"恢复失败: {e}")
        return False

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
    
    quota_input = input("磁盘配额(MB，0表示无限制): ").strip()
    try:
        quota_mb = int(quota_input) if quota_input else 0
    except ValueError:
        print("配额必须是数字，使用默认值0")
        quota_mb = 0
    
    encrypt_password = input("加密密码？(Y/n): ").strip().lower()
    encrypt = not (encrypt_password == 'n')
    
    return add_user(username, password, home_dir, permissions, quota_mb, encrypt)

def main():
    parser = argparse.ArgumentParser(description='FTP用户管理工具')
    subparsers = parser.add_subparsers(dest='command', help='命令')
    
    # 添加用户
    add_parser = subparsers.add_parser('add', help='添加用户')
    add_parser.add_argument('username', help='用户名')
    add_parser.add_argument('password', help='密码')
    add_parser.add_argument('--dir', help='用户目录')
    add_parser.add_argument('--perms', help='权限', default='elradfmw')
    add_parser.add_argument('--quota', type=int, help='磁盘配额(MB)', default=0)
    add_parser.add_argument('--no-encrypt', action='store_true', help='不加密密码')
    
    # 删除用户
    del_parser = subparsers.add_parser('del', help='删除用户')
    del_parser.add_argument('username', help='用户名')
    
    # 修改密码
    passwd_parser = subparsers.add_parser('passwd', help='修改密码')
    passwd_parser.add_argument('username', help='用户名')
    passwd_parser.add_argument('password', help='新密码')
    
    # 列出用户
    list_parser = subparsers.add_parser('list', help='列出用户')
    list_parser.add_argument('--show-passwords', action='store_true', help='显示密码')
    
    # 备份
    subparsers.add_parser('backup', help='备份用户数据')
    
    # 恢复
    restore_parser = subparsers.add_parser('restore', help='恢复用户数据')
    restore_parser.add_argument('backup_file', help='备份文件路径')
    
    # 交互式添加
    subparsers.add_parser('interactive', help='交互式添加用户')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == 'add':
        dir_path = args.dir if args.dir else os.path.join(BASE_DIR, "ftp_share", args.username)
        add_user(args.username, args.password, dir_path, args.perms, args.quota, not args.no_encrypt)
    
    elif args.command == 'del':
        delete_user(args.username)
    
    elif args.command == 'passwd':
        change_password(args.username, args.password)
    
    elif args.command == 'list':
        list_users(args.show_passwords)
    
    elif args.command == 'backup':
        backup_users()
    
    elif args.command == 'restore':
        restore_users(args.backup_file)
    
    elif args.command == 'interactive':
        interactive_add_user()
    
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
EOF
    
    chmod +x "$HOME/bin/ftp_user_manager.py"
    log "用户管理脚本创建完成"
}

# 创建服务器配置
create_server_config() {
    PORT=$(configure_ports)
    
    cat > "$CONFIG_DIR/server.conf" << EOF
[server]
# 服务器设置
host = 0.0.0.0
port = $PORT
timeout = 300
max_connections = 10
max_connections_per_ip = 3

# 被动端口范围
passive_ports_start = 60000
passive_ports_end = 60100

# 带宽限制（字节/秒）
download_limit = 102400
upload_limit = 102400

# 匿名访问
allow_anonymous = no
anonymous_dir = $FTP_ROOT/anonymous

# 服务器信息
banner = Termux FTP Server - Secure File Transfer
motd_file = $CONFIG_DIR/motd.txt

[security]
# 安全设置
require_ssl = no
ssl_cert = $CONFIG_DIR/cert.pem
ssl_key = $CONFIG_DIR/key.key
max_login_attempts = 3
ban_time = 3600

[logging]
# 日志设置
log_enabled = yes
log_file = $LOG_DIR/ftp_access.log
log_level = INFO
rotate_logs = yes
max_log_size = 10485760

[backup]
# 备份设置
auto_backup = yes
backup_interval = 86400
keep_backups = 7
EOF
    
    # 创建欢迎消息
    cat > "$CONFIG_DIR/motd.txt" << EOF
欢迎使用Termux FTP服务器！
服务器时间: %(date)s
当前连接: %(connections)d
您的IP: %(remote_ip)s
EOF
    
    log "服务器配置创建完成"
}

# 创建启动/停止脚本
create_control_scripts() {
    # 启动脚本
    cat > "$HOME/bin/start_ftp.sh" << EOF
#!/data/data/com.termux/files/usr/bin/bash
# FTP服务器启动脚本

source $HOME/ftp_manager.sh

show_banner
echo "启动FTP服务器..."

# 检查是否已运行
if pgrep -f "ftp_server.py" > /dev/null; then
    echo -e "\${YELLOW}FTP服务器已经在运行中\${NC}"
    echo "PID: \$(pgrep -f "ftp_server.py")"
    exit 1
fi

# 启动服务器
cd \$HOME
nohup python ftp_server.py > "\$LOG_DIR/ftp_server.log" 2>&1 &

# 等待启动
sleep 2

# 检查是否启动成功
if pgrep -f "ftp_server.py" > /dev/null; then
    echo -e "\${GREEN}FTP服务器启动成功！\${NC}"
    
    # 显示连接信息
    IP=\$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -1)
    if [ -z "\$IP" ]; then
        IP="127.0.0.1"
    fi
    
    echo ""
    echo "连接信息:"
    echo "地址: ftp://\$IP:\$(grep '^port = ' \$CONFIG_DIR/server.conf | cut -d'=' -f2 | tr -d ' ')"
    echo "被动端口范围: 60000-60100"
    echo ""
    echo "查看日志: tail -f \$LOG_DIR/ftp_server.log"
else
    echo -e "\${RED}FTP服务器启动失败\${NC}"
    echo "请检查日志: cat \$LOG_DIR/ftp_server.log"
fi
EOF
    
    # 停止脚本
    cat > "$HOME/bin/stop_ftp.sh" << EOF
#!/data/data/com.termux/files/usr/bin/bash
# FTP服务器停止脚本

source $HOME/ftp_manager.sh

show_banner
echo "停止FTP服务器..."

# 查找并停止进程
PIDS=\$(pgrep -f "ftp_server.py")
if [ -z "\$PIDS" ]; then
    echo -e "\${YELLOW}FTP服务器未运行\${NC}"
    exit 0
fi

# 停止进程
for PID in \$PIDS; do
    echo "停止进程 \$PID..."
    kill -TERM \$PID 2>/dev/null
    sleep 1
    if ps -p \$PID > /dev/null; then
        kill -KILL \$PID 2>/dev/null
    fi
done

# 确认停止
if pgrep -f "ftp_server.py" > /dev/null; then
    echo -e "\${RED}无法停止FTP服务器\${NC}"
else
    echo -e "\${GREEN}FTP服务器已停止\${NC}"
fi
EOF
    
    # 状态检查脚本
    cat > "$HOME/bin/ftp_status.sh" << EOF
#!/data/data/com.termux/files/usr/bin/bash
# FTP服务器状态检查脚本

source $HOME/ftp_manager.sh

show_banner
echo "FTP服务器状态检查..."

# 检查进程
if pgrep -f "ftp_server.py" > /dev/null; then
    echo -e "\${GREEN}✓ FTP服务器正在运行\${NC}"
    
    # 显示进程信息
    echo ""
    echo "进程信息:"
    pgrep -f "ftp_server.py" | xargs ps -o pid,user,start_time,etime,cmd
    
    # 显示连接信息
    echo ""
    echo "连接信息:"
    IP=\$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -1)
    if [ -z "\$IP" ]; then
        IP="127.0.0.1"
    fi
    
    PORT=\$(grep '^port = ' "\$CONFIG_DIR/server.conf" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    PORT=\${PORT:-2121}
    
    echo "地址: ftp://\$IP:\$PORT"
    echo "被动端口范围: 60000-60100"
    
    # 显示用户数量
    if [ -f "\$USERS_FILE" ]; then
        USER_COUNT=\$(jq 'length' "\$USERS_FILE" 2>/dev/null || echo "0")
        echo "已配置用户: \$USER_COUNT"
    fi
    
    # 显示日志文件大小
    echo ""
    echo "日志信息:"
    if [ -f "\$LOG_DIR/ftp_server.log" ]; then
        LOG_SIZE=\$(du -h "\$LOG_DIR/ftp_server.log" | cut -f1)
        echo "服务器日志: \$LOG_SIZE"
    fi
    
    if [ -f "\$LOG_DIR/ftp_access.log" ]; then
        ACCESS_SIZE=\$(du -h "\$LOG_DIR/ftp_access.log" | cut -f1)
        echo "访问日志: \$ACCESS_SIZE"
    fi
else
    echo -e "\${RED}✗ FTP服务器未运行\${NC}"
fi

# 检查端口监听
echo ""
echo "端口监听状态:"
PORT=\$(grep '^port = ' "\$CONFIG_DIR/server.conf" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
PORT=\${PORT:-2121}
if netstat -tuln 2>/dev/null | grep -q ":\$PORT "; then
    echo -e "\${GREEN}✓ 端口 \$PORT 正在监听\${NC}"
else
    echo -e "\${RED}✗ 端口 \$PORT 未监听\${NC}"
fi

# 显示权限状态
PERM_STATUS=\$(check_permissions)
echo ""
echo "权限状态:"
case \$PERM_STATUS in
    "root"|"su_root")
        echo -e "\${GREEN}✓ Root权限已获取\${NC}"
        ;;
    "sudo")
        echo -e "\${CYAN}✓ Sudo权限可用\${NC}"
        ;;
    "shizuku")
        echo -e "\${PURPLE}✓ Shizuku权限可用\${NC}"
        ;;
    *)
        echo -e "\${YELLOW}⚠ 普通用户模式\${NC}"
        ;;
esac
EOF
    
    chmod +x "$HOME/bin/start_ftp.sh"
    chmod +x "$HOME/bin/stop_ftp.sh"
    chmod +x "$HOME/bin/ftp_status.sh"
    
    log "控制脚本创建完成"
}

# 创建系统服务（根据权限优化）
create_service_file() {
    PERM_STATUS=$(check_permissions)
    
    mkdir -p "$HOME/.termux/boot"
    
    if [ "$PERM_STATUS" = "root" ] || [ "$PERM_STATUS" = "su_root" ]; then
        # 有Root权限时创建系统级启动脚本
        echo -e "${YELLOW}检测到Root权限，是否创建系统级启动服务？(y/N): ${NC}"
        read -r create_system_service
        
        if [ "$create_system_service" = "y" ] || [ "$create_system_service" = "Y" ]; then
            log "创建系统级启动服务..."
            
            # 创建init.d脚本
            cat > "/data/local/tmp/ftp_server.sh" << 'EOF'
#!/system/bin/sh
# FTP服务器系统启动脚本

sleep 30  # 等待系统启动完成

# 检查网络
if ! ping -c 1 8.8.8.8 > /dev/null 2>&1; then
    exit 0
fi

# 启动FTP服务器
su -c "cd /data/data/com.termux/files/home && nohup python ftp_server.py > /data/data/com.termux/files/home/ftp_logs/system_boot.log 2>&1 &"
EOF
            
            chmod +x "/data/local/tmp/ftp_server.sh"
            
            # 尝试添加到启动项
            if [ -d "/data/adb/service.d" ]; then
                cp "/data/local/tmp/ftp_server.sh" "/data/adb/service.d/99ftp_server.sh"
                chmod +x "/data/adb/service.d/99ftp_server.sh"
                echo -e "${GREEN}已添加到Magisk启动项${NC}"
            fi
        fi
    fi
    
    # Termux级别的启动脚本（无Root也能用）
    cat > "$HOME/.termux/boot/start_ftp" << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
# Termux开机自动启动FTP服务器

sleep 15  # 等待Termux启动完成

# 检查网络
if ! ping -c 1 8.8.8.8 > /dev/null 2>&1; then
    exit 0
fi

# 启动FTP服务器
cd $HOME
nohup python ftp_server.py > "$HOME/ftp_logs/boot.log" 2>&1 &
EOF
    
    chmod +x "$HOME/.termux/boot/start_ftp"
    log "启动脚本创建完成"
}

# 高级设置菜单
advanced_settings_menu() {
    show_banner
    echo -e "${PURPLE}高级设置 (需要Root/Shizuku权限)${NC}"
    echo ""
    echo "1. 配置系统防火墙"
    echo "2. 设置系统级自启动"
    echo "3. 优化网络性能"
    echo "4. 查看系统连接"
    echo "5. 备份系统配置"
    echo "6. 恢复系统配置"
    echo "7. 修复权限问题"
    echo "0. 返回主菜单"
    echo ""
    echo -n "请输入选择 [0-7]: "
}

# 配置系统防火墙
configure_firewall() {
    show_banner
    echo -e "${YELLOW}配置系统防火墙${NC}"
    echo ""
    
    PORT=$(grep '^port = ' "$CONFIG_DIR/server.conf" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    PORT=${PORT:-2121}
    
    echo "当前FTP端口: $PORT"
    echo ""
    echo "防火墙选项:"
    echo "1. 开放FTP端口"
    echo "2. 关闭FTP端口"
    echo "3. 查看防火墙状态"
    echo "4. 开放被动端口范围(60000-60100)"
    echo "0. 返回"
    echo ""
    echo -n "请选择: "
    read -r firewall_choice
    
    case $firewall_choice in
        1)
            echo "开放端口 $PORT..."
            run_privileged "iptables -A INPUT -p tcp --dport $PORT -j ACCEPT"
            run_privileged "iptables -A OUTPUT -p tcp --sport $PORT -j ACCEPT"
            echo -e "${GREEN}端口 $PORT 已开放${NC}"
            ;;
        2)
            echo "关闭端口 $PORT..."
            run_privileged "iptables -D INPUT -p tcp --dport $PORT -j ACCEPT 2>/dev/null"
            run_privileged "iptables -D OUTPUT -p tcp --sport $PORT -j ACCEPT 2>/dev/null"
            echo -e "${YELLOW}端口 $PORT 已关闭${NC}"
            ;;
        3)
            echo "防火墙状态:"
            run_privileged "iptables -L -n | grep -E '(ACCEPT|DROP|REJECT)'"
            ;;
        4)
            echo "开放被动端口范围 60000-60100..."
            for p in $(seq 60000 60100); do
                run_privileged "iptables -A INPUT -p tcp --dport $p -j ACCEPT"
                run_privileged "iptables -A OUTPUT -p tcp --sport $p -j ACCEPT"
            done
            echo -e "${GREEN}被动端口范围已开放${NC}"
            ;;
    esac
    
    echo ""
    read -p "按回车键继续..."
}

# 优化网络性能
optimize_network() {
    show_banner
    echo -e "${YELLOW}优化网络性能${NC}"
    echo ""
    
    echo "网络优化选项:"
    echo "1. 优化TCP参数"
    echo "2. 增加连接限制"
    echo "3. 启用数据包转发"
    echo "4. 设置MTU优化"
    echo "0. 返回"
    echo ""
    echo -n "请选择: "
    read -r network_choice
    
    case $network_choice in
        1)
            echo "优化TCP参数..."
            run_privileged "sysctl -w net.ipv4.tcp_window_scaling=1"
            run_privileged "sysctl -w net.ipv4.tcp_timestamps=1"
            run_privileged "sysctl -w net.ipv4.tcp_sack=1"
            echo -e "${GREEN}TCP参数已优化${NC}"
            ;;
        2)
            echo "增加连接限制..."
            run_privileged "sysctl -w net.ipv4.ip_local_port_range='1024 65000'"
            run_privileged "sysctl -w net.ipv4.tcp_fin_timeout=30"
            echo -e "${GREEN}连接限制已增加${NC}"
            ;;
        3)
            echo "启用数据包转发..."
            run_privileged "sysctl -w net.ipv4.ip_forward=1"
            echo -e "${GREEN}数据包转发已启用${NC}"
            ;;
        4)
            echo "设置MTU优化..."
            # 尝试找到活动网络接口
            iface=$(run_privileged "ip route | grep default | awk '{print \$5}'")
            if [ -n "$iface" ]; then
                run_privileged "ip link set $iface mtu 1500"
                echo -e "${GREEN}接口 $iface 的MTU已设置为1500${NC}"
            else
                echo -e "${RED}未找到网络接口${NC}"
            fi
            ;;
    esac
    
    echo ""
    read -p "按回车键继续..."
}

# 安装FTP服务器
install_ftp_server() {
    show_banner
    echo -e "${YELLOW}开始安装FTP服务器...${NC}"
    echo ""
    
    # 检查并创建目录
    check_dirs
    
    # 安装依赖
    install_dependencies
    
    # 创建各种脚本和配置
    create_ftp_server_script
    create_user_manager_script
    create_server_config
    create_control_scripts
    create_service_file
    
    # 创建初始用户
    echo ""
    echo -e "${YELLOW}创建初始管理员用户...${NC}"
    read -p "请输入管理员用户名 [默认: admin]: " admin_user
    admin_user=${admin_user:-admin}
    
    read -sp "请输入管理员密码: " admin_pass
    echo
    read -sp "请确认管理员密码: " admin_pass_confirm
    echo
    
    if [ "$admin_pass" != "$admin_pass_confirm" ]; then
        echo -e "${RED}密码不匹配！${NC}"
        return 1
    fi
    
    # 使用正确的参数格式调用用户管理脚本
    python "$HOME/bin/ftp_user_manager.py" add "$admin_user" --dir "$FTP_ROOT/admin" --perms "elradfmw" "$admin_pass"
    
    echo ""
    echo -e "${GREEN}FTP服务器安装完成！${NC}"
    echo ""
    echo "可用命令:"
    echo "  start_ftp.sh      - 启动FTP服务器"
    echo "  stop_ftp.sh       - 停止FTP服务器"
    echo "  ftp_status.sh     - 查看服务器状态"
    echo "  ftp_user_manager.py - 管理FTP用户"
    echo ""
    
    # 显示权限状态和建议
    PERM_STATUS=$(check_permissions)
    if [ "$PERM_STATUS" != "normal" ]; then
        echo -e "${CYAN}高级功能建议:${NC}"
        echo "  您可以使用高级设置(选项15)来优化网络和防火墙配置"
    fi
    
    log "FTP服务器安装完成"
}

# 启动FTP服务器
start_ftp_server() {
    "$HOME/bin/start_ftp.sh"
}

# 停止FTP服务器
stop_ftp_server() {
    "$HOME/bin/stop_ftp.sh"
}

# 添加FTP用户
add_ftp_user() {
    show_banner
    echo -e "${YELLOW}添加FTP用户${NC}"
    echo ""
    
    python "$HOME/bin/ftp_user_manager.py" interactive
}

# 删除FTP用户
delete_ftp_user() {
    show_banner
    echo -e "${YELLOW}删除FTP用户${NC}"
    echo ""
    
    read -p "请输入要删除的用户名: " username
    
    if [ -z "$username" ]; then
        echo -e "${RED}用户名不能为空${NC}"
        return
    fi
    
    python "$HOME/bin/ftp_user_manager.py" del "$username"
}

# 修改用户密码
change_user_password() {
    show_banner
    echo -e "${YELLOW}修改用户密码${NC}"
    echo ""
    
    read -p "请输入用户名: " username
    read -sp "请输入新密码: " new_password
    echo
    read -sp "请确认新密码: " confirm_password
    echo
    
    if [ "$new_password" != "$confirm_password" ]; then
        echo -e "${RED}密码不匹配！${NC}"
        return
    fi
    
    python "$HOME/bin/ftp_user_manager.py" passwd "$username" "$new_password"
}

# 查看所有用户
list_all_users() {
    show_banner
    echo -e "${YELLOW}所有FTP用户${NC}"
    echo ""
    
    python "$HOME/bin/ftp_user_manager.py" list
}

# 查看服务器状态
view_server_status() {
    "$HOME/bin/ftp_status.sh"
}

# 查看访问日志
view_access_log() {
    show_banner
    echo -e "${YELLOW}FTP访问日志${NC}"
    echo ""
    
    if [ -f "$LOG_DIR/ftp_access.log" ]; then
        echo "最后50行日志:"
        echo "==============================="
        tail -50 "$LOG_DIR/ftp_access.log"
    else
        echo -e "${YELLOW}暂无访问日志${NC}"
    fi
    
    echo ""
    read -p "按回车键继续..."
}

# 备份用户数据
backup_user_data() {
    show_banner
    echo -e "${YELLOW}备份用户数据${NC}"
    echo ""
    
    backup_file=$(python "$HOME/bin/ftp_user_manager.py" backup)
    
    if [ -n "$backup_file" ]; then
        echo ""
        echo -e "${GREEN}备份完成！${NC}"
        echo "备份文件: $backup_file"
    fi
}

# 恢复用户数据
restore_user_data() {
    show_banner
    echo -e "${YELLOW}恢复用户数据${NC}"
    echo ""
    
    # 查找备份文件
    echo "可用的备份文件:"
    find "$CONFIG_DIR/backups" -name "*.json" 2>/dev/null | sort -r | head -10
    
    echo ""
    read -p "请输入备份文件路径: " backup_file
    
    if [ -z "$backup_file" ]; then
        echo -e "${RED}备份文件不能为空${NC}"
        return
    fi
    
    python "$HOME/bin/ftp_user_manager.py" restore "$backup_file"
}

# 卸载FTP服务器
uninstall_ftp_server() {
    show_banner
    echo -e "${RED}卸载FTP服务器${NC}"
    echo ""
    
    echo -e "${YELLOW}警告：这将删除FTP服务器配置和脚本${NC}"
    read -p "确定要卸载吗？(y/N): " confirm
    
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "操作取消"
        return
    fi
    
    # 停止服务器
    echo "停止FTP服务器..."
    if [ -f "$HOME/bin/stop_ftp.sh" ]; then
        "$HOME/bin/stop_ftp.sh" > /dev/null 2>&1
    else
        # 手动停止进程
        PIDS=$(pgrep -f "ftp_server.py" 2>/dev/null)
        if [ -n "$PIDS" ]; then
            for PID in $PIDS; do
                kill -TERM "$PID" 2>/dev/null
                sleep 1
            done
        fi
    fi
    
    # 删除文件
    echo "删除配置文件..."
    [ -d "$CONFIG_DIR" ] && rm -rf "$CONFIG_DIR"
    
    echo "删除日志文件..."
    [ -d "$LOG_DIR" ] && rm -rf "$LOG_DIR"
    
    echo "删除脚本..."
    [ -f "$HOME/ftp_server.py" ] && rm -f "$HOME/ftp_server.py"
    [ -f "$HOME/bin/ftp_user_manager.py" ] && rm -f "$HOME/bin/ftp_user_manager.py"
    [ -f "$HOME/bin/start_ftp.sh" ] && rm -f "$HOME/bin/start_ftp.sh"
    [ -f "$HOME/bin/stop_ftp.sh" ] && rm -f "$HOME/bin/stop_ftp.sh"
    [ -f "$HOME/bin/ftp_status.sh" ] && rm -f "$HOME/bin/ftp_status.sh"
    [ -f "$HOME/.termux/boot/start_ftp" ] && rm -f "$HOME/.termux/boot/start_ftp"
    
    # 如果有root权限，删除系统级启动脚本
    PERM_STATUS=$(check_permissions)
    if [ "$PERM_STATUS" = "root" ] || [ "$PERM_STATUS" = "su_root" ]; then
        echo "删除系统级启动脚本..."
        [ -f "/data/local/tmp/ftp_server.sh" ] && rm -f "/data/local/tmp/ftp_server.sh"
        [ -f "/data/adb/service.d/99ftp_server.sh" ] && rm -f "/data/adb/service.d/99ftp_server.sh"
    fi
    
    echo ""
    echo -e "${GREEN}FTP服务器已卸载${NC}"
}

# 生成连接二维码
generate_qr_code() {
    show_banner
    echo -e "${YELLOW}生成连接二维码${NC}"
    echo ""
    
    # 获取IP地址
    IP=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -1)
    
    if [ -z "$IP" ]; then
        IP="127.0.0.1"
    fi
    
    # 获取端口
    PORT=$(grep '^port = ' "$CONFIG_DIR/server.conf" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    PORT=${PORT:-2121}
    
    # 构建连接字符串
    FTP_URL="ftp://$IP:$PORT"
    echo "FTP服务器地址: $FTP_URL"
    echo ""
    
    # 显示二维码
    if command -v qrencode > /dev/null; then
        echo "二维码:"
        qrencode -t ANSI "$FTP_URL"
    else
        echo "安装qrencode以显示二维码:"
        echo "pkg install qrencode"
    fi
    
    echo ""
    read -p "按回车键继续..."
}

# 配置SFTP模式
configure_sftp_mode() {
    show_banner
    echo -e "${YELLOW}配置SFTP模式${NC}"
    echo ""
    
    echo "SFTP (SSH File Transfer Protocol) 比FTP更安全"
    echo "Termux已经内置了SSH服务器，可以使用SFTP"
    echo ""
    
    # 检查SSH是否运行
    if pgrep -f "sshd" > /dev/null; then
        echo -e "${GREEN}SSH服务器正在运行${NC}"
    else
        echo -e "${YELLOW}SSH服务器未运行${NC}"
        echo "启动SSH服务器..."
        sshd
        sleep 2
    fi
    
    # 获取SSH端口
    SSH_PORT=$(grep "^Port" "$PREFIX/etc/ssh/sshd_config" 2>/dev/null | awk '{print $2}')
    SSH_PORT=${SSH_PORT:-8022}
    
    # 获取IP地址
    IP=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -1)
    
    if [ -z "$IP" ]; then
        IP="127.0.0.1"
    fi
    
    echo ""
    echo "SFTP连接信息:"
    echo "地址: sftp://$IP:$SSH_PORT"
    echo "用户名: $(whoami)"
    echo "密码: 您的Termux密码"
    echo ""
    echo "使用FileZilla等客户端连接时:"
    echo "协议: SFTP"
    echo "主机: $IP"
    echo "端口: $SSH_PORT"
    echo ""
    
    read -p "按回车键继续..."
}

# 高级设置主函数
advanced_settings() {
    while true; do
        advanced_settings_menu
        
        read -r choice
        
        case $choice in
            1)
                configure_firewall
                ;;
            2)
                echo -e "${YELLOW}设置系统级自启动${NC}"
                echo ""
                create_service_file
                ;;
            3)
                optimize_network
                ;;
            4)
                echo -e "${YELLOW}查看系统连接${NC}"
                echo ""
                run_privileged "netstat -tuln | grep -E '(:21|:22|:2121|:60000)'"
                echo ""
                read -p "按回车键继续..."
                ;;
            5)
                echo -e "${YELLOW}备份系统配置${NC}"
                echo ""
                backup_file="/sdcard/ftp_system_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
                run_privileged "tar -czf $backup_file $CONFIG_DIR $LOG_DIR $HOME/ftp_server.py $HOME/bin/ftp_*.sh 2>/dev/null"
                echo -e "${GREEN}系统配置已备份到: $backup_file${NC}"
                echo ""
                read -p "按回车键继续..."
                ;;
            6)
                echo -e "${YELLOW}恢复系统配置${NC}"
                echo ""
                read -p "请输入备份文件路径: " backup_file
                if [ -f "$backup_file" ]; then
                    run_privileged "tar -xzf $backup_file -C /"
                    echo -e "${GREEN}系统配置已恢复${NC}"
                else
                    echo -e "${RED}备份文件不存在${NC}"
                fi
                echo ""
                read -p "按回车键继续..."
                ;;
            7)
                echo -e "${YELLOW}修复权限问题${NC}"
                echo ""
                run_privileged "chmod -R 755 $CONFIG_DIR $LOG_DIR $FTP_ROOT"
                echo -e "${GREEN}权限已修复${NC}"
                echo ""
                read -p "按回车键继续..."
                ;;
            0)
                return
                ;;
            *)
                echo -e "${RED}无效的选择，请重新输入${NC}"
                ;;
        esac
    done
}

# 主函数
main() {
    while true; do
        show_banner
        show_menu
        
        read -r choice
        
        case $choice in
            1)
                install_ftp_server
                ;;
            2)
                start_ftp_server
                ;;
            3)
                stop_ftp_server
                ;;
            4)
                add_ftp_user
                ;;
            5)
                delete_ftp_user
                ;;
            6)
                change_user_password
                ;;
            7)
                list_all_users
                ;;
            8)
                view_server_status
                ;;
            9)
                view_access_log
                ;;
            10)
                backup_user_data
                ;;
            11)
                restore_user_data
                ;;
            12)
                uninstall_ftp_server
                ;;
            13)
                generate_qr_code
                ;;
            14)
                configure_sftp_mode
                ;;
            15)
                PERM_STATUS=$(check_permissions)
                if [ "$PERM_STATUS" != "normal" ]; then
                    advanced_settings
                else
                    echo -e "${RED}此功能需要Root或Shizuku权限${NC}"
                    sleep 2
                fi
                ;;
            0)
                echo "再见！"
                exit 0
                ;;
            *)
                echo -e "${RED}无效的选择，请重新输入${NC}"
                ;;
        esac
        
        echo ""
        read -p "按回车键返回菜单..."
    done
}

# 如果直接运行脚本，执行主函数
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main
fi
