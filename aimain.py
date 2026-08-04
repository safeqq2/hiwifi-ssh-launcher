import base64
import hashlib
import hmac
import json
import socket
import time
import requests
from urllib.parse import urljoin

# 常量
LOCAL_TOKEN_URL = "/local-ssh/api?method=get"
ROUTER_INFO_URL = "/cgi-bin/turbo/proxy/router_info"
LOCAL_SSH_URL = "/local-ssh/api?method=valid&data=%s"

RETRY = 10
SLEEP_SECOND = 10

# 全局变量
address = "192.168.199.1"

# 自定义异常
class ErrorSystemBusy(Exception):
    pass

def fmt_print_fln(format_str, *args):
    """对应 Go 的 fmtPrintFln：打印并换行"""
    print(format_str % args if args else format_str)

def fmt_print(*args):
    """对应 Go 的 fmtPrint"""
    print(*args, end='')

def generate_url(api, *args):
    """生成完整 URL"""
    api = api % args if args else api
    return "http://" + address + api

def http_get(url):
    """发送 GET 请求，返回解析后的 JSON 字典，出错时抛出异常"""
    # Go 代码中对 '+' 做了替换，这里保持一致
    url = url.replace('+', '%2B')
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
    except requests.RequestException as e:
        raise Exception(f"HTTP request failed: {e}")

    body = resp.text
    if "系统忙，请稍后重试" in body:
        raise ErrorSystemBusy("系统忙，请稍后重试")

    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        raise Exception(f"JSON parse error: {body}")

    return data

def get_uuid():
    """获取路由器 UUID"""
    url = generate_url(ROUTER_INFO_URL)
    data = http_get(url)
    # 原结构: {"data": {"uuid": "..."}}
    return data['data']['uuid']

def get_local_token():
    """获取 local_token"""
    url = generate_url(LOCAL_TOKEN_URL)
    data = http_get(url)
    # 原结构: {"data": "..."}
    return data['data']

def token_to_msg(local_token):
    """将 local_token 解码并处理时间戳"""
    try:
        decoded = base64.b64decode(local_token).decode('utf-8')
    except Exception as e:
        raise Exception(f"base64 decode error: {e}")

    parts = decoded.split(',')
    if len(parts) < 3:
        raise Exception("Invalid token format")

    # 原 Go：将第3个字段（索引2）转为 int 并 +1
    try:
        timestamp = int(parts[2])
    except ValueError:
        raise Exception("Invalid timestamp")
    timestamp += 1
    parts[2] = str(timestamp)

    # 只取前三个字段组合成消息
    msg_str = ','.join(parts[:3])
    return msg_str.encode('utf-8')

def sha1_sum(uuid_str):
    """计算 UUID 的 SHA1 摘要（20字节）"""
    return hashlib.sha1(uuid_str.encode('utf-8')).digest()

def hmac_sha1_sum(msg, key):
    """HMAC-SHA1 计算"""
    return hmac.new(key, msg, hashlib.sha1).digest()

def get_cloud_token(uuid, local_token):
    """生成 cloud_token"""
    msg = token_to_msg(local_token)
    key = sha1_sum(uuid)
    expected_mac = hmac_sha1_sum(msg, key)
    cloud_token = base64.b64encode(expected_mac).decode('utf-8')
    return cloud_token

def get_local_ssh(cloud_token):
    """获取 SSH 临时端口"""
    url = generate_url(LOCAL_SSH_URL, cloud_token)
    data = http_get(url)
    result = data.get('data', '')
    if "Success: ssh port is " not in result:
        raise Exception(f"Unknown error: {result}")
    port = result.replace("Success: ssh port is ", "").strip()
    return port

def launch_ssh():
    """主流程：重试获取 SSH 端口"""
    local_token = ""
    uuid = ""
    cloud_token = ""

    for i in range(RETRY + 1):
        if i != 0:
            time.sleep(SLEEP_SECOND)
            fmt_print_fln("----------------------------------------------------------------")
            fmt_print_fln("第%d次重试", i)

        try:
            fmt_print_fln("开始获取UUID")
            uuid = get_uuid()
            fmt_print_fln("获取uuid成功: %s", uuid)

            fmt_print_fln("开始获取local_token")
            local_token = get_local_token()
            fmt_print_fln("获取local_token成功: %s", local_token)

            fmt_print_fln("开始生成cloud_token")
            cloud_token = get_cloud_token(uuid, local_token)
            fmt_print_fln("生成cloud_token成功: %s", cloud_token)

            fmt_print_fln("开始获取local_ssh")
            port = get_local_ssh(cloud_token)
            fmt_print_fln("获取local_ssh成功，端口号: %s，有效期5分钟，请及时更改为永久ssh", port)
            return

        except ErrorSystemBusy as e:
            fmt_print_fln("系统忙，请稍后重试")
            continue
        except Exception as e:
            fmt_print_fln("出错: %v", e)
            continue

    fmt_print_fln("获取local_ssh出错，请检查IP是否有误，UUID，LocalToken是否正常获取")
    fmt_print_fln("极路由IP为: %s", address)
    fmt_print_fln("UUID为: %s", uuid)
    fmt_print_fln("LocalToken为: %s", local_token)
    fmt_print_fln("CloudToken为: %s", cloud_token)

def main():
    global address

    while True:
        user_input = input("请输入极路由管理IP，然后按回车继续(不输入则默认192.168.199.1): ").strip()
        if not user_input:
            user_input = "192.168.199.1"
        # 简单验证 IP 格式（可增强）
        try:
            socket.inet_aton(user_input)
        except socket.error:
            fmt_print_fln("输入非合法IP，请重新输入")
            continue
        address = user_input
        fmt_print_fln("极路由IP为: %s", address)
        break

    launch_ssh()

    input("按回车退出...")

if __name__ == "__main__":
    main()
