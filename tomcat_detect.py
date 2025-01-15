import os

# 定义要检查的 Tomcat 配置文件路径
TOMCAT_CONFIG_PATH = "/path/to/tomcat/conf"  # 替换为 Tomcat 的实际配置目录路径
TOMCAT_SERVER_XML = "server.xml"
TOMCAT_WEB_XML = "web.xml"
TOMCAT_USERS_XML = "tomcat-users.xml"
CATALINA_POLICY = "catalina.policy"

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

# 检查 server.xml 配置
def check_server_xml():
    server_xml_path = os.path.join(TOMCAT_CONFIG_PATH, TOMCAT_SERVER_XML)
    if not check_file_exists(server_xml_path):
        return

    config_lines = read_file(server_xml_path)

    # 检查是否配置了 HTTPS
    if not any("<Connector port=\"443\"" in line and "SSLEnabled=\"true\"" in line for line in config_lines):
        results.append("建议在 server.xml 中启用 HTTPS 配置（443 端口，SSLEnabled=true）")

    # 检查是否禁用了 AJP 连接器
    if any("<Connector port=\"8009\"" in line for line in config_lines):
        results.append("建议禁用 AJP 连接器（8009 端口），除非明确需要")

    # 检查是否配置了安全的 maxThreads 和 acceptCount
    if not any("maxThreads=\"" in line for line in config_lines):
        results.append("建议在 server.xml 中的 Connector 节点配置 maxThreads 参数")
    if not any("acceptCount=\"" in line for line in config_lines):
        results.append("建议在 server.xml 中的 Connector 节点配置 acceptCount 参数")

    # 检查是否启用了地址绑定限制
    if not any("address=\"127.0.0.1\"" in line for line in config_lines):
        results.append("建议在 Connector 节点中启用 address=\"127.0.0.1\" 限制")

# 检查 web.xml 配置
def check_web_xml():
    web_xml_path = os.path.join(TOMCAT_CONFIG_PATH, TOMCAT_WEB_XML)
    if not check_file_exists(web_xml_path):
        return

    config_lines = read_file(web_xml_path)

    # 检查是否禁用了默认的样例应用
    if not any("<servlet-name>default</servlet-name>" in line for line in config_lines):
        results.append("建议禁用默认样例应用以减少潜在攻击面")

    # 检查是否设置了 session 超时时间
    if not any("<session-timeout>" in line for line in config_lines):
        results.append("建议在 web.xml 中设置 session 超时时间")

    # 检查是否启用了 HTTP 方法限制
    if not any("<http-method>TRACE</http-method>" in line for line in config_lines):
        results.append("建议禁用 TRACE 方法以防止跨站脚本攻击")

# 检查 tomcat-users.xml 配置
def check_tomcat_users_xml():
    tomcat_users_path = os.path.join(TOMCAT_CONFIG_PATH, TOMCAT_USERS_XML)
    if not check_file_exists(tomcat_users_path):
        return

    config_lines = read_file(tomcat_users_path)

    # 检查是否设置了强口令的管理账户
    if not any("username" in line and "password" in line for line in config_lines):
        results.append("建议在 tomcat-users.xml 文件中设置强口令的管理账户")

    # 检查是否禁用了不必要的用户权限
    if any("role" in line and "manager-gui" in line for line in config_lines):
        results.append("建议限制管理用户角色权限，仅授予必要的最小权限")

# 检查 catalina.policy 配置
def check_catalina_policy():
    catalina_policy_path = os.path.join(TOMCAT_CONFIG_PATH, CATALINA_POLICY)
    if not check_file_exists(catalina_policy_path):
        return

    config_lines = read_file(catalina_policy_path)

    # 检查是否启用了严格的安全策略
    if not any("grant {" in line for line in config_lines):
        results.append("建议在 catalina.policy 文件中启用必要的安全策略")

# 检查文件和目录权限
def check_file_permissions():
    try:
        for root, dirs, files in os.walk(TOMCAT_CONFIG_PATH):
            for file in files:
                file_path = os.path.join(root, file)
                file_stat = os.stat(file_path)
                if file_stat.st_mode & 0o077:
                    results.append(f"配置文件 {file_path} 权限过宽（建议设置为 640 或更严格）")
    except Exception as e:
        results.append(f"无法检查文件权限: {e}")

# 检查日志配置
def check_logging():
    logging_path = os.path.join(TOMCAT_CONFIG_PATH, "logging.properties")
    if not check_file_exists(logging_path):
        return

    config_lines = read_file(logging_path)

    # 检查日志级别是否合理
    if not any(".level = INFO" in line or ".level = WARNING" in line for line in config_lines):
        results.append("建议设置适当的日志级别（INFO 或更严格）以确保日志记录安全")

# 主函数
def main():
    print("正在进行 Tomcat 基线安全检测...\n")

    check_server_xml()
    check_web_xml()
    check_tomcat_users_xml()
    check_catalina_policy()
    check_file_permissions()
    check_logging()

    if results:
        print("检测到以下安全问题:")
        for issue in results:
            print(f"- {issue}")
    else:
        print("恭喜，没有检测到安全问题！")

if __name__ == "__main__":
    main()