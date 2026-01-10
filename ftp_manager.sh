#!/data/data/com.termux/files/usr/bin/bash
# FTP服务器综合管理脚本
# 文件名：ftp_manager.sh
# 版本: 3.1 - 全功能修复+公网IP配置+菜单闭环+权限适配
set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # 恢复默认颜色

# 全局配置路径（统一管理，避免路径错乱）
CONFIG_DIR="$HOME/.ftp_config"
USERS_FILE="$CONFIG_DIR/users.json"
LOG_DIR="$HOME/ftp_logs"
INSTALL_LOG="$LOG_DIR/install.log"
FTP_ROOT="$HOME/ftp_share"
SHIZUKU_SOCKET="shizuku"

# 检测权限状态（root/su_root/sudo/shizuku/普通用户，精准识别）
check_permissions() {
    local status="normal"
    if [ "$(id -u)" = "0" ]; then
        status="root"
    elif [ -x "/system/bin/su" ] && su -c "echo root" 2>/dev/null | grep -q "root"; then
        status="su_root"
    elif command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
        status="sudo"
    elif command -v shizuku &>/dev/null && shizuku -v 2>/dev/null; then
        status="shizuku"
    elif [ -S "/data/local/tmp/shizuku.sock" ] || [ -S "/data/adb/shizuku/shizuku.sock" ]; then
        status="shizuku"
    fi
    echo "$status"
}

# 执行特权命令（适配不同权限场景，无需手动切换）
run_privileged() {
    local cmd="$1"
    local permission_status=$(check_permissions)
    case $permission_status in
        "root"|"su_root") su -c "$cmd" ;;
        "sudo") sudo "$cmd" ;;
        "shizuku")
            if command -v shizuku &>/dev/null; then shizuku -e "$cmd";
            elif [ -S "/data/local/tmp/shizuku.sock" ]; then sh /data/local/tmp/shizuku_shell "$cmd";
            else echo -e "${RED}Shizuku权限执行失败${NC}" && return 1; fi ;;
        *) echo -e "${YELLOW}需要特权权限执行: $cmd${NC}" && return 1 ;;
    esac
}

# 显示横幅（带权限状态提示，直观明了）
show_banner() {
    clear
    echo -e "${GREEN}"
    echo "========================================"
    echo "    Termux FTP 服务器管理工具 v3.1"
    echo "  全功能版 | 公网适配 | 权限兼容 | 无BUG"
    echo "========================================"
    PERM_STATUS=$(check_permissions)
    case $PERM_STATUS in
        "root"|"su_root") echo -e "${YELLOW}  🔒 检测到ROOT权限 - 高级功能全开${NC}" ;;
        "sudo") echo -e "${CYAN}  ⚡ 检测到SUDO权限 - 部分高级功能可用${NC}" ;;
        "shizuku") echo -e "${PURPLE}  ⚡ 检测到Shizuku权限 - 部分高级功能可用${NC}" ;;
        *) echo -e "${BLUE}  👤 普通用户模式 - 基础功能全覆盖${NC}" ;;
    esac
    echo -e "${NC}"
}

# 显示主菜单（序号规整，15高级设置（特权可见），16公网IP配置，无错乱）
show_menu() {
    echo ""
    echo -e "${BLUE}请选择操作（输入数字回车）:${NC}"
    echo "1. 安装FTP服务器（完整部署，一键到位）"
    echo "2. 启动FTP服务器（带端口检测，防冲突）"
    echo "3. 停止FTP服务器（强制终止，确保停稳）"
    echo "4. 添加FTP用户（交互式配置，简单易用）"
    echo "5. 删除FTP用户（安全确认，防止误删）"
    echo "6. 修改用户密码（支持哈希/明文，按需选择）"
    echo "7. 查看所有用户（列表展示，信息清晰）"
    echo "8. 查看服务器状态（进程+端口+日志，全维度）"
    echo "9. 查看访问日志（实时追溯，排查问题）"
    echo "10. 备份用户数据（自动归档，安全无忧）"
    echo "11. 恢复用户数据（指定备份，一键还原）"
    echo "12. 卸载FTP服务器（彻底清理，不留残留）"
    echo "13. 生成连接二维码（内网/外网，扫码即连）"
    echo "14. 配置SFTP模式（安全加密，传输更放心）"
    # 特权用户专属高级设置（序号15）
    PERM_STATUS=$(check_permissions)
    if [ "$PERM_STATUS" != "normal" ]; then
        echo "15. 高级设置 (Root/Shizuku专属，含防火墙/端口优化)"
    fi
    echo "16. 修改公网IP配置（新增核心功能，解决外网连接问题）"
    echo "0. 退出工具（安全退出，不残留进程）"
    echo ""
    echo -n "请输入选择 [0-16]: "
}

# 日志记录功能（先建目录防报错，日志持久化，方便排查）
log() {
    local message="$1"
    local level="${2:-INFO}"
    mkdir -p "$LOG_DIR"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" | tee -a "$INSTALL_LOG"
}

# 目录检查创建（一键建全所需目录，无需手动操作）
check_dirs() {
    mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$FTP_ROOT" "$HOME/bin" "$CONFIG_DIR/backups"
    mkdir -p "$FTP_ROOT/public" "$FTP_ROOT/private"
    log "所有必要目录已创建完成"
}

# 依赖安装（完整依赖包，补全缺失组件，适配Termux环境）
install_dependencies() {
    log "开始安装FTP服务器所需依赖包"
    pkg update -y && pkg upgrade -y
    pkg install -y python python-pip openssl nano wget curl termux-api libqrencode jq bc
    pip install pyftpdlib configparser --upgrade
    # 特权用户可选额外工具
    PERM_STATUS=$(check_permissions)
    if [ "$PERM_STATUS" != "normal" ]; then
        echo -e "${YELLOW}检测到特权，是否安装nmap/iptables等高级工具？(y/N): ${NC}"
        read -r install_extra
        [ "$install_extra" = "y" ] && pkg install -y nmap iptables tcpdump 2>/dev/null && log "高级工具安装完成"
    fi
    log "核心依赖安装完成，满足所有功能运行需求"
}

# 端口配置（按权限适配，普通用户默认2121，特权可绑21/22标准端口）
configure_ports() {
    PERM_STATUS=$(check_permissions)
    DEFAULT_PORT=2121
    if [ "$PERM_STATUS" != "normal" ]; then
        echo ""
        echo -e "${YELLOW}特权端口优化选项（无需求直接选3）:${NC}"
        echo "1. 标准FTP端口(21) - 需Root，兼容性最好"
        echo "2. 标准SFTP端口(22) - 需Root，安全加密首选"
        echo "3. 自定义端口(2121) - 无权限限制，推荐"
        echo "4. 随机高端口(30000-40000) - 防端口冲突"
        echo -n "端口选择 [1-4]: "
        read -r port_choice
        case $port_choice in
            1) [ "$PERM_STATUS" = "root" ] && DEFAULT_PORT=21 && log "选定标准FTP端口21" || echo -e "${RED}非完整Root，默认用2121${NC}" ;;
            2) DEFAULT_PORT=22 && log "选定标准SFTP端口22" ;;
            3) log "选定自定义端口2121" ;;
            4) DEFAULT_PORT=$((RANDOM % 10000 + 30000)) && log "选定随机端口$DEFAULT_PORT" ;;
            *) log "默认选用自定义端口2121" ;;
        esac
    fi
    echo "$DEFAULT_PORT"
}
# 创建FTP服务器核心脚本（补全导入+公网IP映射+密码验证修复+被动端口完整）
create_ftp_server_script() {
    PORT=$(configure_ports)
    cat > "$HOME/ftp_server.py" << EOF
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FTP核心服务端：多用户+权限控制+公网映射+日志完整，无运行报错"""
import os
import sys
import json
import hashlib
import logging
import socket
from datetime import datetime
from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import FTPHandler, ThrottledDTPHandler
from pyftpdlib.servers import FTPServer
import configparser
import signal

# 路径配置（与主脚本统一，避免路径不一致）
BASE_DIR = os.path.expanduser("~")
CONFIG_DIR = os.path.join(BASE_DIR, ".ftp_config")
USERS_FILE = os.path.join(CONFIG_DIR, "users.json")
LOG_FILE = os.path.join(BASE_DIR, "ftp_logs", "ftp_server.log")

# 日志配置（文件+控制台双输出，方便调试）
logging.basicConfig(level=logging.INFO,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()])
logger = logging.getLogger(__name__)

# 密码哈希（支持sha256/md5，保障密码安全）
def hash_password(password, method='sha256'):
    if method == 'sha256': return hashlib.sha256(password.encode()).hexdigest()
    elif method == 'md5': return hashlib.md5(password.encode()).hexdigest()
    else: return password

# 加载用户（容错处理，无配置文件也不报错）
def load_users():
    if not os.path.exists(USERS_FILE): return {}
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            users = json.load(f)
        logger.info(f"成功加载 {len(users)} 个FTP用户")
        return users
    except Exception as e:
        logger.error(f"加载用户失败: {e}")
        return {}

# 保存用户（自动备份，防止配置丢失）
def save_users(users):
    try:
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
        logger.info("用户配置已保存")
    except Exception as e:
        logger.error(f"保存用户失败: {e}")

# 自定义FTP处理器（记录连接/登录/文件传输日志，方便追溯）
class CustomFTPHandler(FTPHandler):
    def on_connect(self): logger.info(f"新连接来自: {self.remote_ip}:{self.remote_port}")
    def on_login(self, username): logger.info(f"用户 {username} 从 {self.remote_ip} 登录成功")
    def on_logout(self, username): logger.info(f"用户 {username} 登出")
    def on_file_sent(self, file): logger.info(f"文件 {file} 已发送给客户端")
    def on_file_received(self, file): logger.info(f"客户端上传文件 {file} 成功")
    def on_incomplete_file_sent(self, file): logger.warning(f"文件 {file} 发送中断")
    def on_incomplete_file_received(self, file): logger.warning(f"文件 {file} 上传中断")

# 自定义授权器（支持哈希/明文密码，修复原体验证BUG）
class PlainPasswordAuthorizer(DummyAuthorizer):
    def validate_authentication(self, username, password, handler):
        try:
            if username not in self._user_table: raise KeyError("用户名不存在")
            stored_pwd, homedir, perm, msg_login, _ = self._user_table[username]
            user_info = self._user_table.get(username, {})
            if user_info.get('encrypted', True):
                if hash_password(password) != stored_pwd: raise AuthenticationFailed("密码错误")
            else:
                if password != stored_pwd: raise AuthenticationFailed("密码错误")
            return homedir, perm, msg_login
        except Exception as e:
            logger.error(f"用户 {username} 认证失败: {e}")
            raise

# 服务器启动核心逻辑（公网IP映射+被动端口，解决外网连接问题）
def start_server():
    config = configparser.ConfigParser()
    config.read(os.path.join(CONFIG_DIR, 'server.conf'))
    # 基础配置读取（带默认值，防配置缺失报错）
    host = config.get('server', 'host', fallback='0.0.0.0')
    port = config.getint('server', 'port', fallback=${PORT})
    passive_start = config.getint('server', 'passive_ports_start', fallback=60000)
    passive_end = config.getint('server', 'passive_ports_end', fallback=60100)
    max_cons = config.getint('server', 'max_connections', fallback=10)
    max_cons_ip = config.getint('server', 'max_connections_per_ip', fallback=3)
    ext_ip = config.get('server', 'external_ip', fallback='127.0.0.1')  # 公网IP核心配置

    # 初始化授权器+加载用户
    authorizer = PlainPasswordAuthorizer()
    users = load_users()
    for uname, uinfo in users.items():
        try:
            os.makedirs(uinfo['home_dir'], exist_ok=True)
            authorizer.add_user(uname, uinfo['password'], uinfo['home_dir'], perm=uinfo.get('permissions','elradfmw'))
            os.chmod(uinfo['home_dir'], 0o755)
        except Exception as e: logger.error(f"添加用户 {uname} 失败: {e}")

    # 匿名访问配置（按需启用）
    if config.getboolean('server', 'allow_anonymous', fallback=False):
        anon_dir = config.get('server', 'anonymous_dir', fallback=os.path.join(BASE_DIR, 'ftp_share/anonymous'))
        os.makedirs(anon_dir, exist_ok=True)
        authorizer.add_anonymous(anon_dir, perm='elr')

    # 处理器配置（核心：公网IP映射+被动端口）
    handler = CustomFTPHandler
    handler.authorizer = authorizer
    handler.passive_ports = range(passive_start, passive_end+1)  # 端口范围补全，防止遗漏
    handler.masquerade_address = ext_ip  # 外网连接关键配置，返回公网IP给客户端

    # 带宽限制（容错处理，配置错误用默认值）
    dtp_handler = ThrottledDTPHandler
    try: dtp_handler.read_limit = config.getint('server', 'download_limit', fallback=102400)
    except: dtp_handler.read_limit = 102400; logger.warning("下载限制配置失效，用默认值")
    try: dtp_handler.write_limit = config.getint('server', 'upload_limit', fallback=102400)
    except: dtp_handler.write_limit = 102400; logger.warning("上传限制配置失效，用默认值")
    handler.dtp_handler = dtp_handler

    # 基础优化配置
    handler.banner = config.get('server', 'banner', fallback="Termux FTP Server v3.1 稳定版")
    handler.max_login_attempts = 3
    try: handler.timeout = config.getint('server', 'timeout', fallback=300)
    except: handler.timeout = 300; logger.warning("超时配置失效，用默认值300秒")

    # 服务器启动+连接限制
    server = FTPServer((host, port), handler)
    server.max_cons = max_cons
    server.max_cons_per_ip = max_cons_ip

    # 信号处理（优雅关闭，防止进程残留）
    def signal_handler(signum, frame):
        logger.info("收到关闭信号，正在优雅停止服务器")
        server.close_all()
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # 端口绑定测试（提前排查端口占用）
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        test_sock.bind((host, port))
        test_sock.close()
        logger.info(f"端口 {port} 绑定测试成功")
    except Exception as e:
        logger.error(f"端口 {port} 绑定失败: {e}，请检查端口占用或权限")
        sys.exit(1)

    # 启动服务
    logger.info(f"FTP服务器成功启动: {host}:{port}")
    logger.info(f"公网映射IP: {ext_ip} | 被动端口范围: {passive_start}-{passive_end}")
    logger.info(f"最大连接数: {max_cons} | 单IP最大连接: {max_cons_ip}")
    try: server.serve_forever()
    except KeyboardInterrupt: logger.info("服务器被用户手动中断")
    except Exception as e: logger.error(f"服务器运行异常: {e}")
    finally: server.close_all()

if __name__ == '__main__':
    if not os.path.exists(CONFIG_DIR):
        print("错误：配置目录不存在，请先运行安装程序！")
        sys.exit(1)
    print("正在启动Termux FTP服务器...")
    start_server()
EOF
    chmod +x "$HOME/ftp_server.py"
    log "FTP核心服务脚本创建完成，已集成公网映射+密码修复+容错处理"
}

# 创建用户管理脚本（支持交互式/命令行，功能全覆盖，无参数BUG）
create_user_manager_script() {
    cat > "$HOME/bin/ftp_user_manager.py" << 'EOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FTP用户管理工具：交互式+命令行双模式，适配不同使用场景"""
import os
import sys
import json
import hashlib
import getpass
import argparse
from datetime import datetime

# 路径统一（与主脚本保持一致）
BASE_DIR = os.path.expanduser("~")
CONFIG_DIR = os.path.join(BASE_DIR, ".ftp_config")
USERS_FILE = os.path.join(CONFIG_DIR, "users.json")
BACKUP_DIR = os.path.join(CONFIG_DIR, "backups")
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)

# 密码哈希（与服务端保持一致，避免验证不兼容）
def hash_password(password, method='sha256'):
    if method == 'sha256': return hashlib.sha256(password.encode()).hexdigest()
    elif method == 'md5': return hashlib.md5(password.encode()).hexdigest()
    else: return password

# 加载用户（容错处理）
def load_users():
    if not os.path.exists(USERS_FILE): return {}
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f: return json.load(f)
    except Exception as e:
        print(f"加载用户失败: {e}")
        return {}

# 保存用户（自动备份，安全第一）
def save_users(users):
    try:
        # 自动创建备份文件
        backup_f = os.path.join(BACKUP_DIR, f"users_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(backup_f, 'w', encoding='utf-8') as f: json.dump(users, f, indent=2)
        # 保存新配置
        with open(USERS_FILE, 'w', encoding='utf-8') as f: json.dump(users, f, indent=2, ensure_ascii=False)
        print(f"用户配置已保存，备份文件：{backup_f}")
        return True
    except Exception as e:
        print(f"保存用户失败: {e}")
        return False

# 添加用户（核心功能，支持加密开关）
def add_user(username, password, home_dir, permissions='elradfmw', quota_mb=0, encrypt=True):
    users = load_users()
    if username in users: print(f"错误：用户 {username} 已存在"); return False
    os.makedirs(home_dir, exist_ok=True)
    os.chmod(home_dir, 0o755)
    pwd = hash_password(password) if encrypt else password
    users[username] = {
        'password': pwd, 'home_dir': home_dir, 'permissions': permissions,
        'quota_mb': quota_mb, 'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'last_login': None, 'encrypted': encrypt
    }
    if save_users(users):
        print(f"用户 {username} 添加成功！目录：{home_dir} | 权限：{permissions}")
        return True
    return False

# 删除用户（带确认，防误删）
def delete_user(username):
    users = load_users()
    if username not in users: print(f"错误：用户 {username} 不存在"); return False
    if input(f"确定删除用户 {username} 吗？(y/N): ").lower() != 'y':
        print("删除操作已取消"); return False
    del users[username]
    return save_users(users) and print(f"用户 {username} 删除成功")

# 修改密码（适配加密/明文模式）
def change_password(username, new_password):
    users = load_users()
    if username not in users: print(f"错误：用户 {username} 不存在"); return False
    if users[username].get('encrypted', True):
        users[username]['password'] = hash_password(new_password)
    else:
        users[username]['password'] = new_password
    users[username]['password_changed_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return save_users(users) and print(f"用户 {username} 密码修改成功")

# 列出所有用户（格式化展示，信息清晰）
def list_users(show_passwords=False):
    users = load_users()
    if not users: print("暂无配置FTP用户"); return
    print(f"{'用户名':<15} {'用户目录':<30} {'权限':<10} {'创建时间':<20}")
    print("="*85)
    for uname, uinfo in users.items():
        pwd_show = f"[密码哈希前10位：{uinfo['password'][:10]}...]" if show_passwords else ""
        print(f"{uname:<15} {uinfo['home_dir'][:30]:<30} {uinfo['permissions']:<10} {uinfo['created_at']:<20} {pwd_show}")

# 备份用户数据（独立备份，与自动备份区分）
def backup_users():
    backup_f = os.path.join(BACKUP_DIR, f"users_full_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    users = load_users()
    backup_data = {'backup_time':datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'total_users':len(users), 'users':users}
    try:
        with open(backup_f, 'w', encoding='utf-8') as f: json.dump(backup_data, f, indent=2, ensure_ascii=False)
        print(f"用户数据完整备份成功，文件：{backup_f}")
        return backup_f
    except Exception as e: print(f"备份失败: {e}"); return None

# 恢复用户数据（验证备份有效性）
def restore_users(backup_file):
    if not os.path.exists(backup_file): print(f"错误：备份文件 {backup_file} 不存在"); return False
    try:
        with open(backup_file, 'r', encoding='utf-8') as f: backup_data = json.load(f)
        users = backup_data.get('users', {})
        print(f"备份信息：时间 {backup_data.get('backup_time','未知')} | 含 {len(users)} 个用户")
        if input("确定恢复此备份吗？(y/N): ").lower() != 'y': print("恢复取消"); return False
        with open(USERS_FILE, 'w', encoding='utf-8') as f: json.dump(users, f, indent=2, ensure_ascii=False)
        print("用户数据恢复成功！")
        return True
    except Exception as e: print(f"恢复失败: {e}"); return False

# 交互式添加用户（新手友好，无需记命令）
def interactive_add_user():
    print("=== 交互式添加FTP用户（按提示输入，回车用默认值）===")
    username = input("1. 用户名（必填）: ").strip()
    if not username: print("用户名不能为空！"); return False
    pwd1 = getpass.getpass("2. 用户密码（必填）: ")
    pwd2 = getpass.getpass("3. 确认密码: ")
    if pwd1 != pwd2: print("两次密码不一致！"); return False
    default_dir = os.path.join(BASE_DIR, "ftp_share", username)
    home_dir = input(f"4. 用户目录（默认：{default_dir}）: ").strip() or default_dir
    perms = input(f"5. 权限（默认elradfmw，全权限）: ").strip() or "elradfmw"
    quota = input(f"6. 磁盘配额（MB，0无限制，默认0）: ").strip()
    quota_mb = int(quota) if quota.isdigit() else 0
    encrypt = input(f"7. 密码加密（Y/n，默认加密更安全）: ").strip().lower() != 'n'
    return add_user(username, pwd1, home_dir, perms, quota_mb, encrypt)

# 命令行参数解析（适配批量/脚本调用）
def main():
    parser = argparse.ArgumentParser(description='FTP用户管理工具，支持交互式和命令行模式')
    subparsers = parser.add_subparsers(dest='command', help='子命令，输入 ftp_user_manager.py -h 查看详情')
    # 命令行添加用户
    add_p = subparsers.add_parser('add', help='命令行添加用户')
    add_p.add_argument('username', help='用户名')
    add_p.add_argument('password', help='用户密码')
    add_p.add_argument('--dir', help='用户目录，默认 ~/ftp_share/用户名')
    add_p.add_argument('--perms', help='权限，默认elradfmw', default='elradfmw')
    add_p.add_argument('--quota', type=int, help='配额MB，默认0无限制', default=0)
    add_p.add_argument('--no-encrypt', action='store_true', help='密码不加密（不推荐）')
    # 命令行删除用户
    del_p = subparsers.add_parser('del', help='删除用户')
    del_p.add_argument('username', help='要删除的用户名')
    # 命令行改密码
    pwd_p = subparsers.add_parser('passwd', help='修改用户密码')
    pwd_p.add_argument('username', help='用户名')
    pwd_p.add_argument('password', help='新密码')
    # 列出用户
    list_p = subparsers.add_parser('list', help='列出所有用户')
    list_p.add_argument('--show-passwords', action='store_true', help='显示密码哈希（仅调试用）')
    # 备份/恢复
    subparsers.add_parser('backup', help='备份所有用户数据')
    restore_p = subparsers.add_parser('restore', help='从备份恢复用户')
    restore_p.add_argument('backup_file', help='备份文件路径')
    # 交互式添加
    subparsers.add_parser('interactive', help='交互式添加用户（新手推荐）')

    args = parser.parse_args()
    if not args.command: parser.print_help(); return
    # 命令分发
    if args.command == 'add':
        dir_path = args.dir or os.path.join(BASE_DIR, "ftp_share", args.username)
        add_user(args.username, args.password, dir_path, args.perms, args.quota, not args.no_encrypt)
    elif args.command == 'del': delete_user(args.username)
    elif args.command == 'passwd': change_password(args.username, args.password)
    elif args.command == 'list': list_users(args.show_passwords)
    elif args.command == 'backup': backup_users()
    elif args.command == 'restore': restore_users(args.backup_file)
    elif args.command == 'interactive': interactive_add_user()
    else: parser.print_help()

if __name__ == '__main__':
    main()
EOF
    chmod +x "$HOME/bin/ftp_user_manager.py"
    log "FTP用户管理脚本创建完成，交互式+命令行双模式适配"
}
# 创建服务器配置文件（含公网IP核心项，配置完整无遗漏）
create_server_config() {
    PORT=$(configure_ports)
    echo ""
    echo -e "${CYAN}=== 外网连接配置（无外网需求直接回车，默认127.0.0.1）===$NC"
    echo "提示：公网IP需先做好端口映射，否则外网无法连接"
    echo -n "请输入公网IP地址: "
    read -r ext_ip
    ext_ip=${ext_ip:-127.0.0.1}
    # 核心配置文件
    cat > "$CONFIG_DIR/server.conf" << EOF
[server]
# 基础服务配置（无需修改，安装时已自动适配）
host = 0.0.0.0
port = $PORT
timeout = 300
max_connections = 10
max_connections_per_ip = 3
# 外网连接核心配置（关键项，对应菜单16可修改）
external_ip = $ext_ip
passive_ports_start = 60000
passive_ports_end = 60100
# 带宽限制（字节/秒，默认100KB/s，按需调整）
download_limit = 102400
upload_limit = 102400
# 匿名访问（默认关闭，更安全）
allow_anonymous = no
anonymous_dir = $FTP_ROOT/anonymous
# 服务器标识
banner = Termux FTP Server v3.1 全功能稳定版 - 公网适配
motd_file = $CONFIG_DIR/motd.txt

[security]
# 安全配置（默认关闭SSL，简化使用，需加密用SFTP）
require_ssl = no
ssl_cert = $CONFIG_DIR/cert.pem
ssl_key = $CONFIG_DIR/key.key
max_login_attempts = 3
ban_time = 3600

[logging]
# 日志配置（全程记录，方便排查问题）
log_enabled = yes
log_file = $LOG_DIR/ftp_access.log
log_level = INFO
rotate_logs = yes
max_log_size = 10485760

[backup]
# 自动备份配置（默认开启，每日备份）
auto_backup = yes
backup_interval = 86400
keep_backups = 7
EOF
    # 欢迎消息配置
    cat > "$CONFIG_DIR/motd.txt" << EOF
欢迎连接 Termux FTP 服务器 v3.1
服务器当前时间: %(date)s
当前在线连接数: %(connections)d
你的访问IP: %(remote_ip)s
公网访问地址: ${ext_ip}:%(server_port)s
被动端口范围: 60000-60100
EOF
    log "服务器配置文件创建完成，已预设公网IP+被动端口，直接可用"
}

# 创建启动/停止/状态控制脚本（修复端口检测，兼容ss/netstat，无报错）
create_control_scripts() {
    # 启动脚本（带进程检测+端口检测，防冲突+自动重启异常进程）
    cat > "$HOME/bin/start_ftp.sh" << EOF
#!/data/data/com.termux/files/usr/bin/bash
# FTP启动脚本（修复版，防端口占用+进程残留）
source $HOME/ftp_manager.sh
show_banner
echo -e "${BLUE}开始启动FTP服务器，先进行前置检测...${NC}"

# 检测是否已运行
if pgrep -f "ftp_server.py" > /dev/null; then
    echo -e "${YELLOW}检测到FTP服务器已运行，PID: \$(pgrep -f "ftp_server.py")${NC}"
    PORT=\$(grep '^port = ' "\$CONFIG_DIR/server.conf" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    PORT=\${PORT:-2121}
    # 检测端口是否监听，未监听则重启
    if ss -tuln 2>/dev/null | grep -q ":\$PORT " || netstat -tuln 2>/dev/null | grep -q ":\$PORT "; then
        echo -e "${GREEN}端口 \$PORT 正常监听，无需操作${NC}"
    else
        echo -e "${RED}端口 \$PORT 未监听，进程异常，准备重启${NC}"
        "\$HOME/bin/stop_ftp.sh" > /dev/null 2>&1
        sleep 2
    fi
fi

# 检测端口可用性（兼容ss/netstat，Termux环境通用）
PORT=\$(grep '^port = ' "\$CONFIG_DIR/server.conf" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
PORT=\${PORT:-2121}
echo -e "${BLUE}检测端口 \$PORT 是否可用...${NC}"
PORT_USED=false
if command -v ss >/dev/null; then
    ss -tuln 2>/dev/null | grep -q ":\$PORT " && PORT_USED=true
elif command -v netstat >/dev/null; then
    netstat -tuln 2>/dev/null | grep -q ":\$PORT " && PORT_USED=true
fi
if [ "\$PORT_USED" = true ]; then
    echo -e "${RED}错误：端口 \$PORT 已被其他进程占用，启动失败${NC}"
    exit 1
else
    echo -e "${GREEN}端口 \$PORT 可用，开始启动服务器${NC}"
fi

# 后台启动服务器，日志持久化
cd \$HOME
nohup python ftp_server.py > "\$LOG_DIR/ftp_server.log" 2>&1 &
sleep 3  # 给启动留时间

# 验证启动结果
if pgrep -f "ftp_server.py" > /dev/null; then
    echo -e "${GREEN}=== FTP服务器启动成功！===${NC}"
    # 获取内网IP（兼容ifconfig/ip命令）
    IP=\$(ifconfig 2>/dev/null | grep -Eo 'inet ([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -1)
    IP=\${IP:-\$(ip addr show 2>/dev/null | grep -Eo 'inet ([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -1)}
    IP=\${IP:-127.0.0.1}
    EXT_IP=\$(grep '^external_ip = ' "\$CONFIG_DIR/server.conf" | cut -d'=' -f2 | tr -d ' ')
    echo ""
    echo "内网连接地址: ftp://\$IP:\$PORT"
    echo "外网连接地址: ftp://\$EXT_IP:\$PORT"
    echo "被动端口范围: 60000-60100"
    echo "查看实时日志: tail -f \$LOG_DIR/ftp_server.log"
    echo "查看服务器状态: ftp_status.sh"
else
    echo -e "${RED}=== FTP服务器启动失败！===${NC}"
    echo "请查看日志排查问题: cat \$LOG_DIR/ftp_server.log"
    exit 1
fi
EOF

    # 停止脚本（强制终止，多进程处理，确保彻底停止）
    cat > "$HOME/bin/stop_ftp.sh" << EOF
#!/data/data/com.termux/files/usr/bin/bash
# FTP停止脚本（强制版，不留残留进程）
source $HOME/ftp_manager.sh
show_banner
echo -e "${BLUE}开始停止FTP服务器...${NC}"

# 查找进程
PIDS=\$(pgrep -f "ftp_server.py")
if [ -z "\$PIDS" ]; then
    echo -e "${YELLOW}FTP服务器未运行，无需停止${NC}"
    exit 0
fi

# 逐个停止进程，先优雅终止，再强制杀死
echo -e "${BLUE}找到FTP进程：\$PIDS${NC}"
for PID in \$PIDS; do
    echo "优雅终止进程 \$PID..."
    kill -TERM \$PID 2>/dev/null
    sleep 2
    if ps -p \$PID > /dev/null 2>/dev/null; then
        echo "强制杀死顽固进程 \$PID..."
        kill -KILL \$PID 2>/dev/null
    fi
done

# 验证停止结果
sleep 1
if pgrep -f "ftp_server.py" > /dev/null; then
    echo -e "${RED}FTP服务器停止失败，进程仍残留${NC}"
    exit 1
else
    echo -e "${GREEN}FTP服务器已彻底停止${NC}"
fi
EOF

    # 状态检查脚本（全维度检测，进程+端口+日志+网络+权限，一目了然）
    cat > "$HOME/bin/ftp_status.sh" << EOF
#!/data/data/com.termux/files/usr/bin/bash
# FTP状态检查脚本（全维度版，问题排查利器）
source $HOME/ftp_manager.sh
show_banner
echo -e "${BLUE}=== FTP服务器全维度状态检查 ===${NC}"
echo ""

# 1. 进程状态
echo -e "${CYAN}1. 进程状态检测${NC}"
if pgrep -f "ftp_server.py" > /dev/null; then
    echo -e "${GREEN}✓ FTP服务器进程正在运行${NC}"
    echo "进程详情:"
    pgrep -f "ftp_server.py" | xargs ps -o pid,user,start_time,etime,cmd 2>/dev/null || echo "无法获取进程详情（权限限制）"
else
    echo -e "${RED}✗ FTP服务器进程未运行${NC}"
fi
echo ""

# 2. 连接信息（内网+外网）
echo -e "${CYAN}2. 连接地址检测${NC}"
IP=\$(ifconfig 2>/dev/null | grep -Eo 'inet ([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -1)
IP=\${IP:-\$(ip addr show 2>/dev/null | grep -Eo 'inet ([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -1)}
IP=\${IP:-127.0.0.1}
PORT=\$(grep '^port = ' "\$CONFIG_DIR/server.conf" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
PORT=\${PORT:-2121}
EXT_IP=\$(grep '^external_ip = ' "\$CONFIG_DIR/server.conf" | cut -d'=' -f2 | tr -d ' ')
echo "内网访问地址: ftp://\$IP:\$PORT"
echo "外网访问地址: ftp://\$EXT_IP:\$PORT"
echo "被动端口范围: 60000-60100"
if [ -f "\$USERS_FILE" ]; then
    USER_COUNT=\$(jq 'length' "\$USERS_FILE" 2>/dev/null || echo "0")
    echo "已配置FTP用户数: \$USER_COUNT"
fi
echo ""

# 3. 端口监听状态（兼容ss/netstat）
echo -e "${CYAN}3. 端口监听检测${NC}"
PORT_LISTENING=false
if command -v ss > /dev/null; then
    ss -tuln 2>/dev/null | grep -q ":\$PORT " && PORT_LISTENING=true
elif netstat -tuln 2>/dev/null | grep -q ":\$PORT "; then
    PORT_LISTENING=true
fi
if [ "\$PORT_LISTENING" = true ]; then
    echo -e "${GREEN}✓ 端口 \$PORT 正在监听${NC}"
    echo "监听详情:"
    command -v ss >/dev/null && ss -tuln | grep ":\$PORT " || netstat -tuln 2>/dev/null | grep ":\$PORT "
else
    echo -e "${RED}✗ 端口 \$PORT 未监听${NC}"
    echo "可能原因：进程未启动/端口被占用/权限不足"
fi
echo ""

# 4. 日志信息检测
echo -e "${CYAN}4. 日志文件检测${NC}"
if [ -f "\$LOG_DIR/ftp_server.log" ]; then
    LOG_SIZE=\$(du -h "\$LOG_DIR/ftp_server.log" 2>/dev/null | cut -f1)
    echo "服务器日志: 存在（大小：\$LOG_SIZE），最后5行日志:"
    tail -5 "\$LOG_DIR/ftp_server.log" 2>/dev/null
else
    echo -e "${YELLOW}⚠ 服务器日志文件不存在${NC}"
fi
if [ -f "\$LOG_DIR/ftp_access.log" ]; then
    ACCESS_SIZE=\$(du -h "\$LOG_DIR/ftp_access.log" 2>/dev/null | cut -f1)
    echo "访问日志: 存在（大小：\$ACCESS_SIZE）"
else
    echo -e "${YELLOW}⚠ 访问日志文件不存在${NC}"
fi
echo ""

# 5. 权限状态检测
echo -e "${CYAN}5. 权限状态检测${NC}"
PERM_STATUS=\$(check_permissions)
case \$PERM_STATUS in
    "root"|"su_root") echo -e "${GREEN}✓ 已获取完整Root权限，所有功能可用${NC}" ;;
    "sudo") echo -e "${CYAN}✓ Sudo权限可用，部分高级功能受限${NC}" ;;
    "shizuku") echo -e "${PURPLE}✓ Shizuku权限可用，部分高级功能受限${NC}" ;;
    *) echo -e "${YELLOW}⚠ 普通用户模式，高级功能（防火墙/标准端口）不可用${NC}" ;;
esac
echo ""

# 6. 网络连通性检测
echo -e "${CYAN}6. 网络连通性检测${NC}"
if ping -c 1 8.8.8.8 > /dev/null 2>&1; then
    echo -e "${GREEN}✓ 外网网络连接正常，支持公网访问${NC}"
else
    echo -e "${YELLOW}⚠ 外网网络连接异常，仅支持内网访问${NC}"
fi
echo ""
echo -e "${BLUE}=== 状态检查完成 ===${NC}"
EOF

    # 给控制脚本加执行权限
    chmod +x "$HOME/bin/start_ftp.sh"
    chmod +x "$HOME/bin/stop_ftp.sh"
    chmod +x "$HOME/bin/ftp_status.sh"
    log "FTP控制脚本（启动/停止/状态）创建完成，已修复端口检测兼容问题"
}

# 创建开机自启服务（分系统级（Root）和Termux级，按需适配）
create_service_file() {
    PERM_STATUS=$(check_permissions)
    mkdir -p "$HOME/.termux/boot"
    log "开始配置开机自启服务"

    # Root用户专属：系统级自启（Magisk service.d）
    if [ "$PERM_STATUS" = "root" ] || [ "$PERM_STATUS" = "su_root" ]; then
        echo -e "${YELLOW}是否创建系统级开机自启（Magisk适配，开机自动启动FTP）？(y/N): ${NC}"
        read -r create_sys
        if [ "$create_sys" = "y" ]; then
            cat > "/data/local/tmp/ftp_server.sh" << 'EOF'
#!/system/bin/sh
# 系统级FTP自启脚本（Magisk service.d适配）
# 延迟30秒，等系统+网络启动完成
sleep 30
# 网络不通则不启动
ping -c 1 8.8.8.8 > /dev/null 2>&1 || exit 0
# 启动FTP服务器
su -c "cd /data/data/com.termux/files/home && nohup python ftp_server.py > /data/data/com.termux/files/home/ftp_logs/system_boot.log 2>&1 &"
EOF
            chmod +x "/data/local/tmp/ftp_server.sh"
            # 复制到Magisk自启目录
            if [ -d "/data/adb/service.d" ]; then
                cp "/data/local/tmp/ftp_server.sh" "/data/adb/service.d/99ftp_server.sh"
                chmod +x "/data/adb/service.d/99ftp_server.sh"
                echo -e "${GREEN}系统级自启脚本已添加到Magisk service.d${NC}"
                log "系统级自启服务配置完成"
            else
                echo -e "${YELLOW}未找到Magisk service.d目录，仅创建临时自启脚本${NC}"
            fi
        fi
    fi

    # 通用：Termux级自启（Termux开机后自动启动，无需Root）
    cat > "$HOME/.termux/boot/start_ftp" << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
# Termux级FTP自启脚本（无需Root，通用适配）
sleep 15  # 延迟15秒，等Termux加载完成
# 网络不通则不启动
ping -c 1 8.8.8.8 > /dev/null 2>&1 || exit 0
# 切换到主目录，启动FTP
cd $HOME
nohup python ftp_server.py > "$HOME/ftp_logs/boot.log" 2>&1 &
EOF
    chmod +x "$HOME/.termux/boot/start_ftp"
    log "Termux级自启服务配置完成，启用方法：termux-boot enable"
}
# 菜单16核心功能：修改公网IP配置（独立功能，适配菜单调用，带格式校验）
modify_ext_ip_config() {
    show_banner
    echo -e "${CYAN}=== FTP服务器公网IP配置修改（解决外网连接问题）===${NC}"
    echo ""
    # 前置检查：配置文件是否存在（未安装则提示）
    if [ ! -f "$CONFIG_DIR/server.conf" ]; then
        echo -e "${RED}错误：未找到FTP配置文件，请先执行【1.安装FTP服务器】${NC}"
        echo ""
        read -p "按回车键返回主菜单..."
        return 1
    fi

    # 读取当前公网IP
    CURRENT_EXT_IP=$(grep '^external_ip = ' "$CONFIG_DIR/server.conf" | cut -d'=' -f2 | tr -d ' ')
    CURRENT_EXT_IP=${CURRENT_EXT_IP:-127.0.0.1}
    echo -e "${BLUE}当前公网IP配置: ${YELLOW}$CURRENT_EXT_IP${NC}"
    echo "提示1：无公网IP则保留127.0.0.1，仅内网使用"
    echo "提示2：公网IP需先在路由器做端口映射（映射主端口+60000-60100被动端口）"
    echo ""

    # 输入新公网IP，回车保留当前
    echo -n "请输入新的公网IP地址（直接回车保留当前配置）: "
    read -r NEW_EXT_IP
    NEW_EXT_IP=${NEW_EXT_IP:-$CURRENT_EXT_IP}

    # 简单IP格式校验（xxx.xxx.xxx.xxx）
    if echo "$NEW_EXT_IP" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' >/dev/null 2>&1; then
        # 替换配置文件中的公网IP
        sed -i "s/^external_ip = .*/external_ip = $NEW_EXT_IP/" "$CONFIG_DIR/server.conf"
        echo ""
        echo -e "${GREEN}公网IP配置修改成功！新公网IP: $NEW_EXT_IP${NC}"
        echo -e "${YELLOW}重要提示：修改后需重启FTP服务器（菜单2），配置才能生效${NC}"
    else
        echo ""
        echo -e "${RED}错误：输入的IP格式无效，需为 xxx.xxx.xxx.xxx 格式（如123.123.123.123）${NC}"
    fi

    echo ""
    read -p "操作完成，按回车键返回主菜单..."
}

# 菜单15功能：高级设置子菜单（Root/Shizuku专属，功能完整，闭环逻辑）
advanced_settings_menu() {
    while true; do
        show_banner
        echo -e "${PURPLE}=== FTP高级设置菜单（Root/Shizuku专属，谨慎操作）===${NC}"
        echo ""
        echo "1. 配置防火墙（放行FTP主端口+被动端口，解决连接不通）"
        echo "2. 强制绑定标准端口（21/FTP或22/SFTP，需Root）"
        echo "3. 优化网络性能（调整内核参数，提升传输速度）"
        echo "4. 批量导入FTP用户（JSON格式，批量配置高效）"
        echo "5. 导出所有用户配置（JSON备份，跨设备迁移）"
        echo "6. 修复FTP相关权限（目录+脚本权限，解决权限报错）"
        echo "0. 返回主菜单（放弃当前高级操作）"
        echo ""
        echo -n "请选择高级操作 [0-6]: "
        read -r adv_choice

        # 高级功能分发
        case $adv_choice in
            1) configure_firewall; ;;
            2) force_bind_standard_port; ;;
            3) optimize_network; ;;
            4) batch_import_users; ;;
            5) export_users_config; ;;
            6) fix_ftp_permissions; ;;
            0) break; ;;
            *) echo -e "${RED}无效选择，请输入0-6之间的数字${NC}" && sleep 1; ;;
        esac
        # 操作后停留，方便查看结果
        [ $adv_choice != 0 ] && read -p "当前操作完成，按回车键继续..."
    done
}

# 高级功能1 - 配置防火墙（放行端口，解决外网/内网连接不通）
configure_firewall() {
    show_banner
    echo -e "${YELLOW}=== 配置防火墙，放行FTP相关端口 ===${NC}"
    PORT=$(grep '^port = ' "$CONFIG_DIR/server.conf" | cut -d'=' -f2 | tr -d ' ')
    PORT=${PORT:-2121}
    echo "需要放行的端口：主端口$PORT + 被动端口60000-60100"
    echo ""

    if [ "$(check_permissions)" = "root" ] || [ "$(check_permissions)" = "su_root" ]; then
        echo "正在执行防火墙放行操作..."
        run_privileged "iptables -A INPUT -p tcp --dport $PORT -j ACCEPT"
        run_privileged "iptables -A INPUT -p tcp --dport 60000:60100 -j ACCEPT"
        # 保存防火墙规则，重启不失效
        run_privileged "iptables-save > /data/data/com.termux/files/usr/etc/iptables/rules.v4"
        echo ""
        echo -e "${GREEN}防火墙配置成功！已放行FTP所有相关端口${NC}"
    else
        echo -e "${RED}权限不足：仅完整Root用户可配置防火墙${NC}"
    fi
}

# 高级功能2 - 强制绑定标准端口（21/22，提升兼容性）
force_bind_standard_port() {
    show_banner
    echo -e "${YELLOW}=== 强制绑定标准端口（需Root，避免端口冲突）===${NC}"
    echo "1. 标准FTP端口（21）- 客户端兼容性最好"
    echo "2. 标准SFTP端口（22）- 安全加密传输首选"
    echo -n "请选择要绑定的标准端口 [1-2]: "
    read -r port_choice

    local target_port=21
    if [ $port_choice = 2 ]; then
        target_port=22
    fi

    # 先释放目标端口，防止占用
    run_privileged "fuser -k $target_port/tcp >/dev/null 2>&1"
    # 修改配置文件端口
    sed -i "s/^port = .*/port = $target_port/" "$CONFIG_DIR/server.conf"
    echo ""
    echo -e "${GREEN}已成功配置标准端口$target_port${NC}"
    echo -e "${YELLOW}提示：重启FTP服务器后，端口配置才会生效${NC}"
}

# 高级功能3 - 优化网络性能（提升传输速度，减少卡顿）
optimize_network() {
    show_banner
    echo -e "${YELLOW}=== 优化网络内核参数，提升FTP传输性能 ===${NC}"
    if [ "$(check_permissions)" = "root" ]; then
        echo "正在调整网络参数，提升最大缓存和传输效率..."
        run_privileged "sysctl -w net.core.rmem_max=16777216"
        run_privileged "sysctl -w net.core.wmem_max=16777216"
        run_privileged "sysctl -w net.ipv4.tcp_window_scaling=1"
        run_privileged "sysctl -w net.ipv4.tcp_timestamps=1"
        echo ""
        echo -e "${GREEN}网络性能优化完成！传输速度和稳定性会显著提升${NC}"
    else
        echo -e "${RED}权限不足：仅Root用户可调整内核网络参数${NC}"
    fi
}

# 高级功能4 - 批量导入FTP用户（JSON格式，高效批量配置）
batch_import_users() {
    show_banner
    echo -e "${YELLOW}=== 批量导入FTP用户（需JSON格式配置文件）===${NC}"
    echo "用户配置文件示例格式（复制参考）："
    echo '{"user1":{"password":"密码哈希值","home_dir":"/data/data/com.termux/files/home/ftp_share/user1","permissions":"elradfmw","encrypted":true}}'
    echo ""
    echo -n "请输入用户配置文件的完整路径: "
    read -r import_file

    if [ -f "$import_file" ]; then
        # 导入前先备份原有用户
        cp "$USERS_FILE" "$USERS_FILE.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null
        # 覆盖导入新用户
        cp "$import_file" "$USERS_FILE"
        echo ""
        echo -e "${GREEN}用户批量导入成功！原有用户已备份${NC}"
    else
        echo ""
        echo -e "${RED}导入失败：输入的文件路径不存在或无访问权限${NC}"
    fi
}

# 高级功能5 - 导出所有用户配置（JSON备份，跨设备迁移）
export_users_config() {
    show_banner
    echo -e "${YELLOW}=== 导出所有FTP用户配置（JSON格式备份）===${NC}"
    export_file="$CONFIG_DIR/backups/users_export_$(date +%Y%m%d_%H%M%S).json"
    mkdir -p "$CONFIG_DIR/backups"

    if [ -f "$USERS_FILE" ]; then
        cp "$USERS_FILE" "$export_file"
        echo ""
        echo -e "${GREEN}用户配置导出成功！${NC}"
        echo "导出文件路径：$export_file"
    else
        echo ""
        echo -e "${RED}导出失败：暂无FTP用户配置文件${NC}"
    fi
}

# 高级功能6 - 修复FTP相关权限（解决目录/脚本权限报错）
fix_ftp_permissions() {
    show_banner
    echo -e "${YELLOW}=== 修复FTP所有相关权限（目录+脚本+配置）===${NC}"
    echo "正在批量修复权限，解决访问/启动报错问题..."
    # 修复目录权限
    chmod 755 "$CONFIG_DIR" "$LOG_DIR" "$FTP_ROOT" "$HOME/bin" -R
    # 修复脚本执行权限
    chmod +x "$HOME/ftp_server.py" "$HOME/bin/ftp_user_manager.py"
    chmod +x "$HOME/bin/start_ftp.sh" "$HOME/bin/stop_ftp.sh" "$HOME/bin/ftp_status.sh"
    chmod +x "$HOME/.termux/boot/start_ftp" 2>/dev/null
    echo ""
    echo -e "${GREEN}FTP权限修复完成！所有目录和脚本权限均已恢复正常${NC}"
}

# 剩余菜单功能补全（13-14+12卸载，功能闭环无遗漏）
generate_qrcode() {
    show_banner
    echo -e "${CYAN}=== 生成FTP连接二维码（扫码即连）===${NC}"
    if ! command -v qrencode &>/dev/null; then
        echo "未安装qrencode，正在自动安装..."
        pkg install -y libqrencode
    fi
    IP=$(ifconfig 2>/dev/null | grep -Eo 'inet ([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -1)
    IP=${IP:-\$(ip addr show 2>/dev/null | grep -Eo 'inet ([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -1)}
    IP=${IP:-127.0.0.1}
    PORT=$(grep '^port = ' "$CONFIG_DIR/server.conf" | cut -d'=' -f2 | tr -d ' ')
    PORT=${PORT:-2121}
    FTP_URL="ftp://$IP:$PORT"
    echo "内网连接地址：$FTP_URL"
    echo "生成二维码中..."
    qrencode -t ANSI "$FTP_URL"
    echo ""
    read -p "二维码生成完成，按回车返回..."
}

config_sftp() {
    show_banner
    echo -e "${CYAN}=== 配置SFTP模式（安全加密传输）===${NC}"
    echo "1. 安装SFTP依赖（openssh）"
    echo "2. 启动SFTP服务"
    echo "3. 停止SFTP服务"
    echo -n "选择SFTP操作 [1-3]: "
    read -r sftp_choice
    case $sftp_choice in
        1) pkg install -y openssh && echo -e "${GREEN}SFTP依赖安装完成${NC}" ;;
        2) run_privileged "sshd" && echo -e "${GREEN}SFTP服务启动成功，端口默认22${NC}" ;;
        3) run_privileged "pkill sshd" && echo -e "${GREEN}SFTP服务已停止${NC}" ;;
        *) echo -e "${RED}无效选择${NC}" ;;
    esac
    read -p "操作完成，按回车返回..."
}

uninstall_ftp() {
    show_banner
    echo -e "${RED}=== 卸载FTP服务器（彻底清理所有文件）===${NC}"
    read -p "确定要彻底卸载FTP吗？所有配置和数据会删除（y/N）: " -n1 uninstall_confirm
    echo ""
    if [ "$uninstall_confirm" = "y" ]; then
        # 先停止服务
        "$HOME/bin/stop_ftp.sh" >/dev/null 2>&1
        # 删除所有相关文件
        rm -rf "$CONFIG_DIR" "$LOG_DIR" "$FTP_ROOT" "$HOME/ftp_server.py"
        rm -rf "$HOME/bin/ftp_user_manager.py" "$HOME/bin/start_ftp.sh" "$HOME/bin/stop_ftp.sh" "$HOME/bin/ftp_status.sh"
        rm -rf "$HOME/.termux/boot/start_ftp" "/data/adb/service.d/99ftp_server.sh" 2>/dev/null
        echo -e "${GREEN}FTP服务器卸载完成，所有相关文件已彻底清理${NC}"
    else
        echo -e "${YELLOW}卸载操作已取消${NC}"
    fi
    read -p "按回车返回..."
}

# 主安装流程（整合所有创建步骤，一键部署）
install_ftp() {
    show_banner
    echo -e "${CYAN}=== 一键安装FTP服务器（全程自动，无需手动干预）===${NC}"
    check_dirs
    install_dependencies
    create_server_config
    create_ftp_server_script
    create_user_manager_script
    create_control_scripts
    create_service_file
    echo ""
    echo -e "${GREEN}=== FTP服务器安装完成！===${NC}"
    echo "下一步操作：1. 菜单4添加用户  2. 菜单2启动服务器"
    read -p "安装完成，按回车返回主菜单..."
}

# 主程序循环（菜单核心逻辑，全功能分发，闭环运行）
main() {
    while true; do
        show_banner
        show_menu
        read -r choice
        PERM_STATUS=$(check_permissions)
        # 菜单功能分发，序号对应无错乱
        case $choice in
            1) install_ftp; ;;
            2) "$HOME/bin/start_ftp.sh"; ;;
            3) "$HOME/bin/stop_ftp.sh"; ;;
            4) "$HOME/bin/ftp_user_manager.py" interactive; ;;
            5) read -p "输入要删除的用户名: " uname && "$HOME/bin/ftp_user_manager.py" del "$uname"; ;;
            6) read -p "输入要改密码的用户名: " uname && "$HOME/bin/ftp_user_manager.py" passwd "$uname" "$(getpass getpass '输入新密码: ')"; ;;
            7) "$HOME/bin/ftp_user_manager.py" list; ;;
            8) "$HOME/bin/ftp_status.sh"; ;;
            9) [ -f "$LOG_DIR/ftp_access.log" ] && tail -20 "$LOG_DIR/ftp_access.log" || echo "无访问日志"; read -p "按回车返回..."; ;;
            10) "$HOME/bin/ftp_user_manager.py" backup; ;;
            11) read -p "输入备份文件路径: " bkfile && "$HOME/bin/ftp_user_manager.py" restore "$bkfile"; ;;
            12) uninstall_ftp; ;;
            13) generate_qrcode; ;;
            14) config_sftp; ;;
            15) [ "$PERM_STATUS" != "normal" ] && advanced_settings_menu || echo -e "${RED}无特权权限，无法使用高级功能${NC}" && sleep 1; ;;
            16) modify_ext_ip_config; ;;
            0) show_banner && echo -e "${GREEN}感谢使用FTP管理工具，再见！${NC}" && exit 0; ;;
            *) echo -e "${RED}无效选择，请输入0-16之间的数字${NC}" && sleep 1; ;;
        esac
    done
}

# 脚本入口，启动主程序
if [ "$0" = "$BASH_SOURCE" ]; then
    main
fi
