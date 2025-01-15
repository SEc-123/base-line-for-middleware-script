import os
import subprocess

# 定义要检查的 Apache 配置文件路径
APACHE_CONFIG_PATH = "/etc/apache2/apache2.conf"  # 根据系统调整路径
VHOSTS_CONFIG_DIR = "/etc/apache2/sites-enabled"  # 虚拟主机配置目录

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
def check_apache_global_config():
    if not check_file_exists(APACHE_CONFIG_PATH):
        return

    config_lines = read_file(APACHE_CONFIG_PATH)

    # 检查 ServerTokens 设置
    if not any("ServerTokens Prod" in line for line in config_lines):
        results.append("建议设置 ServerTokens 为 Prod 以减少敏感信息泄露")

    # 检查 ServerSignature 设置
    if not any("ServerSignature Off" in line for line in config_lines):
        results.append("建议设置 ServerSignature 为 Off 以隐藏服务器版本信息")

    # 检查是否禁用了目录浏览
    if any("Options Indexes" in line for line in config_lines):
        results.append("建议禁用目录浏览 (Indexes)，以避免泄露目录结构")

    # 检查 FollowSymLinks 是否存在
    if any("Options FollowSymLinks" in line for line in config_lines):
        results.append("建议在 Options 中避免使用 FollowSymLinks，以降低符号链接漏洞风险")

    # 检查是否启用了 HTTPS
    if not any("SSLEngine On" in line for line in config_lines):
        results.append("建议启用 HTTPS 以确保数据传输的安全性")

    # 检查 Timeout 配置
    if not any("Timeout" in line for line in config_lines):
        results.append("建议显式设置 Timeout 值（推荐 60 秒以内）以减少拒绝服务攻击风险")

# 检查虚拟主机配置
def check_vhosts_config():
    if not os.path.isdir(VHOSTS_CONFIG_DIR):
        results.append(f"虚拟主机配置目录不存在: {VHOSTS_CONFIG_DIR}")
        return

    for file_name in os.listdir(VHOSTS_CONFIG_DIR):
        file_path = os.path.join(VHOSTS_CONFIG_DIR, file_name)
        if os.path.isfile(file_path):
            config_lines = read_file(file_path)

            # 检查每个虚拟主机是否启用了 HTTPS
            if not any("SSLEngine On" in line for line in config_lines):
                results.append(f"虚拟主机文件 {file_name} 未启用 HTTPS")

            # 检查是否限制访问权限
            if not any("Require all denied" in line or "AllowOverride None" in line for line in config_lines):
                results.append(f"虚拟主机文件 {file_name} 未设置访问限制")

            # 检查 HSTS（HTTP Strict Transport Security）是否启用
            if not any("Header always set Strict-Transport-Security" in line for line in config_lines):
                results.append(f"虚拟主机文件 {file_name} 未启用 HSTS（建议强制 HTTPS 使用）")

# 检查模块加载
def check_loaded_modules():
    try:
        loaded_modules = subprocess.check_output(["apachectl", "-M"], stderr=subprocess.STDOUT).decode()

        # 检查是否启用了不必要的模块
        unnecessary_modules = ["autoindex_module", "status_module"]
        for module in unnecessary_modules:
            if module in loaded_modules:
                results.append(f"检测到启用了不必要的模块: {module}，建议禁用")

        # 检查安全模块是否启用
        required_modules = ["headers_module", "rewrite_module", "ssl_module", "security2_module"]
        for module in required_modules:
            if module not in loaded_modules:
                results.append(f"建议启用必要的模块: {module}")
    except Exception as e:
        results.append(f"无法检查已加载模块: {e}")

# 检查日志配置
def check_logging():
    config_lines = read_file(APACHE_CONFIG_PATH)

    if not any("LogLevel" in line for line in config_lines):
        results.append("建议设置 LogLevel 为适当级别（如 warn 或 error）以确保日志记录")

    if not any("ErrorLog" in line for line in config_lines):
        results.append("建议配置 ErrorLog 以记录错误日志")

    if not any("CustomLog" in line for line in config_lines):
        results.append("建议配置 CustomLog 以记录访问日志")

# 检查文件和目录权限
def check_file_permissions():
    try:
        file_stat = os.stat(APACHE_CONFIG_PATH)
        if file_stat.st_mode & 0o077:
            results.append(f"配置文件 {APACHE_CONFIG_PATH} 权限过宽（建议设置为 640 或更严格）")

        if os.path.isdir(VHOSTS_CONFIG_DIR):
            for root, dirs, files in os.walk(VHOSTS_CONFIG_DIR):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_stat = os.stat(file_path)
                    if file_stat.st_mode & 0o077:
                        results.append(f"虚拟主机配置文件 {file_path} 权限过宽（建议设置为 640 或更严格）")
    except Exception as e:
        results.append(f"无法检查文件权限: {e}")

# 检查安全 HTTP 头配置
def check_security_headers():
    config_lines = read_file(APACHE_CONFIG_PATH)

    if not any("Header always set X-Frame-Options" in line for line in config_lines):
        results.append("建议设置 X-Frame-Options 为 DENY 或 SAMEORIGIN 以防止点击劫持攻击")

    if not any("Header always set X-Content-Type-Options" in line for line in config_lines):
        results.append("建议设置 X-Content-Type-Options 为 nosniff 以防止 MIME 类型混淆攻击")

    if not any("Header always set Content-Security-Policy" in line for line in config_lines):
        results.append("建议设置 Content-Security-Policy 以防止 XSS 攻击")

# 主函数
def main():
    print("正在进行 Apache 基线安全检测...\n")

    check_apache_global_config()
    check_vhosts_config()
    check_loaded_modules()
    check_logging()
    check_file_permissions()
    check_security_headers()

    if results:
        print("检测到以下安全问题:")
        for issue in results:
            print(f"- {issue}")
    else:
        print("恭喜，没有检测到安全问题！")

if __name__ == "__main__":
    main()
