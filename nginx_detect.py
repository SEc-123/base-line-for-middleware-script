import os
import subprocess

# 定义要检查的 Nginx 配置文件路径
NGINX_CONFIG_PATH = "/etc/nginx/nginx.conf"  # 根据实际路径调整
NGINX_SITES_DIR = "/etc/nginx/sites-enabled"  # 虚拟主机配置目录

# 定义检查结果存储
results = []

# 检查文件是否存在
def check_file_exists(file_path):
    if not os.path.exists(file_path):
        results.append(f"配置文件不存在: {file_path}")
        return False
    return True

# 读取文件内容
def read_file(file_path):
    try:
        with open(file_path, "r") as file:
            return file.readlines()
    except Exception as e:
        results.append(f"无法读取文件 {file_path}: {e}")
        return []

# 检查全局配置文件
def check_nginx_global_config():
    if not check_file_exists(NGINX_CONFIG_PATH):
        return

    config_lines = read_file(NGINX_CONFIG_PATH)

    # 检查 worker_processes 的适当配置
    if not any("worker_processes" in line for line in config_lines):
        results.append("建议显式设置 worker_processes 为 auto 或适当值")

    # 检查 user 参数是否设置
    if not any(line.strip().startswith("user") for line in config_lines):
        results.append("建议显式设置 user 参数以指定运行 Nginx 的用户")

    # 检查 keepalive_timeout 是否设置
    if not any("keepalive_timeout" in line for line in config_lines):
        results.append("建议设置 keepalive_timeout 参数以减少长时间空闲连接")

    # 检查 HTTPS 强制使用
    if not any("ssl_protocols" in line for line in config_lines):
        results.append("建议在全局配置中设置 ssl_protocols 以强制启用 HTTPS")

    # 检查是否禁用了版本信息泄露
    if not any("server_tokens off" in line.lower() for line in config_lines):
        results.append("建议设置 server_tokens 为 off 以隐藏版本信息")

# 检查虚拟主机配置
def check_vhosts_config():
    if not os.path.isdir(NGINX_SITES_DIR):
        results.append(f"虚拟主机配置目录不存在: {NGINX_SITES_DIR}")
        return

    for file_name in os.listdir(NGINX_SITES_DIR):
        file_path = os.path.join(NGINX_SITES_DIR, file_name)
        if os.path.isfile(file_path):
            config_lines = read_file(file_path)

            # 检查每个虚拟主机是否启用了 HTTPS
            if not any("listen 443 ssl" in line for line in config_lines):
                results.append(f"虚拟主机文件 {file_name} 未启用 HTTPS")

            # 检查是否设置了 HSTS
            if not any("add_header Strict-Transport-Security" in line for line in config_lines):
                results.append(f"虚拟主机文件 {file_name} 未启用 HSTS（建议强制 HTTPS 使用）")

            # 检查是否禁用了目录索引
            if not any("autoindex off" in line for line in config_lines):
                results.append(f"虚拟主机文件 {file_name} 未禁用目录索引（建议添加 autoindex off）")

# 检查日志配置
def check_logging():
    config_lines = read_file(NGINX_CONFIG_PATH)

    if not any("access_log" in line for line in config_lines):
        results.append("建议配置 access_log 以记录访问日志")

    if not any("error_log" in line for line in config_lines):
        results.append("建议配置 error_log 以记录错误日志")

    # 检查日志格式是否安全完整
    if not any("log_format" in line for line in config_lines):
        results.append("建议设置 log_format 参数以确保日志格式包含关键信息")

# 检查文件和目录权限
def check_file_permissions():
    try:
        file_stat = os.stat(NGINX_CONFIG_PATH)
        if file_stat.st_mode & 0o077:
            results.append(f"配置文件 {NGINX_CONFIG_PATH} 权限过宽（建议设置为 640 或更严格）")

        if os.path.isdir(NGINX_SITES_DIR):
            for root, dirs, files in os.walk(NGINX_SITES_DIR):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_stat = os.stat(file_path)
                    if file_stat.st_mode & 0o077:
                        results.append(f"虚拟主机配置文件 {file_path} 权限过宽（建议设置为 640 或更严格）")
    except Exception as e:
        results.append(f"无法检查文件权限: {e}")

# 检查安全 HTTP 头配置
def check_security_headers():
    config_lines = read_file(NGINX_CONFIG_PATH)

    if not any("add_header X-Frame-Options" in line for line in config_lines):
        results.append("建议设置 X-Frame-Options 为 DENY 或 SAMEORIGIN 以防止点击劫持攻击")

    if not any("add_header X-Content-Type-Options" in line for line in config_lines):
        results.append("建议设置 X-Content-Type-Options 为 nosniff 以防止 MIME 类型混淆攻击")

    if not any("add_header Content-Security-Policy" in line for line in config_lines):
        results.append("建议设置 Content-Security-Policy 以防止 XSS 攻击")

# 检查 HTTPS 配置安全性
def check_https_security():
    config_lines = read_file(NGINX_CONFIG_PATH)

    # 检查是否禁用了不安全的协议
    if not any("ssl_protocols TLSv1.2 TLSv1.3" in line for line in config_lines):
        results.append("建议禁用过时的协议（如 TLSv1.0 和 TLSv1.1），仅使用 TLSv1.2 和 TLSv1.3")

    # 检查是否设置了安全加密套件
    if not any("ssl_ciphers" in line for line in config_lines):
        results.append("建议设置 ssl_ciphers 为强加密算法集")

    # 检查是否设置了 ssl_prefer_server_ciphers
    if not any("ssl_prefer_server_ciphers on" in line for line in config_lines):
        results.append("建议启用 ssl_prefer_server_ciphers 以优先使用服务器端加密算法")

# 主函数
def main():
    print("正在进行 Nginx 基线安全检测...\n")

    check_nginx_global_config()
    check_vhosts_config()
    check_logging()
    check_file_permissions()
    check_security_headers()
    check_https_security()

    if results:
        print("检测到以下安全问题:")
        for issue in results:
            print(f"- {issue}")
    else:
        print("恭喜，没有检测到安全问题！")

if __name__ == "__main__":
    main()
