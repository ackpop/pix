#此脚本遵循MIT协议开源 ，脚本为个人学习/技术交流用途
# -*- coding: utf-8 -*-
import ctypes
import os
import re
import subprocess
import sys
import time
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path


PROCESS_IMAGE_NAMES = (
    "Client-Win64-Shipping.exe",
    "Wuthering Waves.exe",
    "WutheringWaves.exe",
)
PROCESS_BASE_NAMES = (
    "Client-Win64-Shipping",
    "Wuthering Waves",
    "WutheringWaves",
    "鸣潮",
)
URL_KEYWORDS = ("gacha", "record", "gacha_id", "record_id")
POLL_INTERVAL = 1.0
WAIT_TIMEOUT = 180
MAX_BUFFER_CHARS = 2_000_000
COLOR_ENABLED = False
COLOR_GREEN = "\033[32m"
COLOR_RED = "\033[31m"
COLOR_CYAN = "\033[36m"
COLOR_YELLOW = "\033[33m"
COLOR_RESET = "\033[0m"

# 可以直接用记事本改这里。留空表示不用。
# 填 Client.log 的完整路径。留空时，脚本会优先尝试自动从游戏进程路径定位。
# 示例：CUSTOM_CLIENT_LOG_PATH = r"D:\Wuthering Waves\Wuthering Waves Game\Client\Saved\Logs\Client.log"
CUSTOM_CLIENT_LOG_PATH = r"D:\Wuthering Waves\Wuthering Waves Game\Client\Saved\Logs\Client.log"

# client.log 的部分内容会被逐字节异或。按存储字节奇偶选择 key 可还原文本。
DECODE_TABLE = bytes((v ^ 0xA5) if v % 2 == 1 else (v ^ 0xEF) for v in range(256))


@dataclass
class GameProcess:
    name: str
    pid: str
    path: Path | None


def enable_terminal_colors():
    global COLOR_ENABLED
    COLOR_ENABLED = sys.stdout.isatty()
    if not COLOR_ENABLED or os.name != "nt":
        return

    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            COLOR_ENABLED = False
            return
        if not kernel32.SetConsoleMode(handle, mode.value | 0x0004):
            COLOR_ENABLED = False
    except Exception:
        COLOR_ENABLED = False


def colored(text, color):
    if not COLOR_ENABLED:
        return text
    return f"{color}{text}{COLOR_RESET}"


def tag(name, color):
    return colored(f"[{name}]", color)


def status(msg):
    sys.stdout.write("\r" + msg.ljust(100))
    sys.stdout.flush()


def line(msg=""):
    print("\r" + msg.ljust(100))


def processing(msg):
    status(f"{tag('PROCESSING', COLOR_CYAN)} {msg}")


def successful(msg):
    line(f"{tag('SUCCESSFUL', COLOR_GREEN)} {msg}")


def failed(msg):
    line(f"{tag('FAILED', COLOR_RED)} {msg}")


def notice(msg):
    line(f"{tag('NOTICE', COLOR_YELLOW)} {msg}")


def decode_encrypted_bytes(raw, skip_header=False):
    data = raw[3:] if skip_header else raw
    return data.translate(DECODE_TABLE)


def text_candidates(raw, skip_header=False):
    """Return both plain and decrypted views so the script works with either log format."""
    chunks = (raw, decode_encrypted_bytes(raw, skip_header))
    texts = []
    for chunk in chunks:
        for encoding in ("utf-8", "gb18030"):
            text = chunk.decode(encoding, errors="ignore")
            if text:
                texts.append(text)
            break
    return texts


def extract_urls(text):
    urls = re.findall(r"https?://[^\s\"'\\<>\[\]]+", text)
    cleaned = (url.rstrip(").,;]}>'\"") for url in urls)
    hits = [url for url in cleaned if any(key in url.lower() for key in URL_KEYWORDS)]
    return list(dict.fromkeys(hits))


def run_powershell(command, timeout=15):
    return subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def parse_process_rows(output):
    rows = []
    for raw_line in output.splitlines():
        parts = raw_line.rstrip("\r\n").split("\t")
        if len(parts) < 3:
            continue
        name, pid, raw_path = parts[0].strip(), parts[1].strip(), parts[2].strip()
        path = Path(raw_path) if raw_path else None
        rows.append(GameProcess(name=name, pid=pid, path=path))
    return rows


def query_process_path_with_winapi(pid):
    if os.name != "nt":
        return None

    try:
        numeric_pid = int(pid)
    except (TypeError, ValueError):
        return None

    process_query_limited_information = 0x1000
    handle = ctypes.windll.kernel32.OpenProcess(
        process_query_limited_information,
        False,
        numeric_pid,
    )
    if not handle:
        return None

    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        ok = ctypes.windll.kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size))
        if not ok:
            return None
        path = Path(buffer.value)
        return path if path.is_file() else None
    except Exception:
        return None
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def query_processes_with_cim():
    filters = " OR ".join(f"Name='{name.replace(chr(39), chr(39) + chr(39))}'" for name in PROCESS_IMAGE_NAMES)
    command = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        f"Get-CimInstance Win32_Process -Filter \"{filters}\" -ErrorAction Stop "
        "| ForEach-Object { \"$($_.Name)`t$($_.ProcessId)`t$($_.ExecutablePath)\" }"
    )
    try:
        result = run_powershell(command)
    except Exception:
        return []
    if result.returncode != 0:
        return []
    return parse_process_rows(result.stdout)


def query_processes_with_get_process():
    names = ",".join("'" + name.replace("'", "''") + "'" for name in PROCESS_BASE_NAMES)
    command = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        f"Get-Process -Name {names} -ErrorAction SilentlyContinue "
        "| ForEach-Object { \"$($_.ProcessName)`t$($_.Id)`t$($_.Path)\" }"
    )
    try:
        result = run_powershell(command)
    except Exception:
        return []
    return parse_process_rows(result.stdout)


def process_priority(row):
    name = (row.name or "").casefold()
    path_name = row.path.name.casefold() if row.path else ""
    value = name + " " + path_name
    if "client-win64-shipping" in value:
        return 0
    if "wuthering waves" in value or "wutheringwaves" in value:
        return 1
    if "鸣潮" in value:
        return 2
    return 3


def find_game_process():
    rows = query_processes_with_cim() + query_processes_with_get_process()
    if not rows:
        return None

    for row in rows:
        if not row.path:
            path = query_process_path_with_winapi(row.pid)
        else:
            path = row.path
        if path and path.is_file():
            row.path = path

    rows = sorted(rows, key=process_priority)
    for row in rows:
        if row.path and row.path.is_file():
            return row

    return rows[0]


def clean_path_text(value):
    text = str(value or "").strip()
    if text.startswith("& "):
        text = text[2:].strip()
    if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
        text = text[1:-1].strip()
    return text


def find_client_log(logs_dir):
    for name in ("Client.log", "client.log"):
        candidate = logs_dir / name
        if candidate.is_file():
            return candidate

    try:
        for child in logs_dir.iterdir():
            if child.is_file() and child.name.casefold() == "client.log":
                return child
    except Exception:
        return None
    return None


def find_log_file_from_exe(exe_path):
    if not exe_path:
        return None

    bases = [exe_path.parent, *exe_path.parents]
    relative_dirs = (
        Path("Saved") / "Logs",
        Path("Client") / "Saved" / "Logs",
        Path("Wuthering Waves Game") / "Client" / "Saved" / "Logs",
        Path("Wuthering Waves") / "Wuthering Waves Game" / "Client" / "Saved" / "Logs",
    )

    seen = set()
    for base in bases:
        for relative in relative_dirs:
            logs_dir = base / relative
            key = str(logs_dir).casefold()
            if key in seen:
                continue
            seen.add(key)
            log_file = find_client_log(logs_dir)
            if log_file:
                return log_file
    return None


def find_log_file_from_user_path(raw_path):
    text = clean_path_text(raw_path)
    if not text:
        return None

    path = Path(text).expanduser()
    if path.is_file() and path.name.casefold() == "client.log":
        return path
    return None


def prompt_for_log_file():
    if not sys.stdin.isatty():
        return None

    print()
    print("没有权限读取游戏进程路径")
    print("请把 Client.log 文件拖到这个窗口后按回车。")
    print("这只会用于本次运行；想永久固定路径请用记事本修改脚本顶部 CUSTOM_CLIENT_LOG_PATH。")
    print("常见位置示例：游戏目录\\Wuthering Waves Game\\Client\\Saved\\Logs\\Client.log")
    try:
        raw_path = input("Client.log 路径: ")
    except EOFError:
        return None
    return find_log_file_from_user_path(raw_path)


def find_log_file(exe_path=None):
    log_file = find_log_file_from_user_path(CUSTOM_CLIENT_LOG_PATH)
    if log_file:
        return log_file

    direct = find_log_file_from_exe(exe_path)
    if direct:
        return direct

    return prompt_for_log_file()


def collect_urls_from_bytes(raw, skip_header=False):
    urls = []
    for text in text_candidates(raw, skip_header):
        urls.extend(extract_urls(text))
    return list(dict.fromkeys(urls))


def find_latest_url_in_tail(log_file, max_bytes=5_000_000):
    try:
        size = log_file.stat().st_size
        with log_file.open("rb") as handle:
            handle.seek(max(0, size - max_bytes))
            raw = handle.read()
    except Exception:
        return None

    urls = collect_urls_from_bytes(raw, skip_header=False)
    return urls[-1] if urls else None


def wait_for_new_url(log_file, timeout, poll_interval):
    offset = log_file.stat().st_size
    raw_buffer = ""
    decoded_buffer = ""
    start = time.time()

    while True:
        elapsed = int(time.time() - start)
        if elapsed > timeout:
            fallback = find_latest_url_in_tail(log_file)
            if fallback:
                notice("未检测到新增写入，使用日志中最近的唤取记录链接。")
                return fallback

            failed("等待超时，没抓到新链接。")
            print("  确认打开的是 唤取记录 页面，然后重新运行脚本。")
            return None

        try:
            size = log_file.stat().st_size
            if size < offset:
                offset = 0
                raw_buffer = ""
                decoded_buffer = ""

            if size > offset:
                with log_file.open("rb") as handle:
                    handle.seek(offset)
                    chunk = handle.read(size - offset)
                offset = size

                raw_buffer += chunk.decode("utf-8", errors="ignore")
                decoded_buffer += decode_encrypted_bytes(chunk).decode("utf-8", errors="ignore")
                raw_buffer = raw_buffer[-MAX_BUFFER_CHARS:]
                decoded_buffer = decoded_buffer[-MAX_BUFFER_CHARS:]

                found = extract_urls(raw_buffer + "\n" + decoded_buffer)
                if found:
                    return found[-1]
        except Exception:
            pass

        processing(f"等待用户打开 唤取记录 页面 已等 {elapsed}s（最多 {timeout}s）")
        time.sleep(poll_interval)


def run():
    print("=" * 64)
    print("鸣潮 - 唤取记录链接提取器")
    print("=" * 64)

    processing("正在查找运行中的游戏进程")
    game_process = find_game_process()
    if game_process is None:
        failed("没找到运行中的游戏进程。")
        print("  请先启动鸣潮，进入游戏主界面后再运行本脚本。")
        return 1

    if game_process.path:
        successful(f"找到游戏: {game_process.path}")
    else:
        successful(f"找到游戏进程: {game_process.name} (PID {game_process.pid})")

    processing("正在定位日志文件")
    log_file = find_log_file(game_process.path)
    if log_file is None:
        failed("没有找到 Client.log。")
        print("  请用记事本修改脚本顶部 CUSTOM_CLIENT_LOG_PATH，填入 Client.log 完整路径。")
        return 1

    successful(f"日志文件: {log_file}")

    print()
    print("-> 现在请在游戏里打开：唤取 -> 唤取记录")
    print("  打开页面时，游戏会把链接写入日志。")
    print()

    url = wait_for_new_url(
        log_file=log_file,
        timeout=WAIT_TIMEOUT,
        poll_interval=POLL_INTERVAL,
    )
    if not url:
        return 1

    print()
    print("=" * 64)
    successful("唤取记录链接已捕获：")
    print()
    print(url)
    print()
    print("=" * 64)
    print("提示：链接有时效，若导入后过期请再打开一次记录页并重新运行脚本。")
    return 0

def pause_before_exit():
    if not sys.stdin.isatty():
        return
    try:
        input("\n按回车键退出...")
    except EOFError:
        pass

def main():
    enable_terminal_colors()
    try:
        return run()
    except KeyboardInterrupt:
        print("\n已取消。")
        return 130
    except Exception as exc:
        print(f"\n脚本发生错误：{exc}")
        return 1
    finally:
        pause_before_exit()


if __name__ == "__main__":
    sys.exit(main())
