# -*- coding: utf-8 -*-
"""HTTP 转发抓包服务 —— 窗口主程序。

双击运行（.pyw 不会弹黑色控制台）。界面包含：
  · 本地监听端口（默认 8089）+ 启动/停止按钮
  · 协议选择 http/https（默认 http）
  · 远程服务地址（IP 或域名）+ 远程服务端口
  · 彩色日志框，每行带 [时:分:秒:毫秒] 时间戳
  · 启动时自动保存连接配置，下次启动自动加载
"""

from __future__ import annotations

import json
import os
import queue
import socket
import sys
import threading
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import forwarder  # noqa: E402

APP_TITLE = "HTTP 转发抓包服务"
CONFIG_NAME = "forwarder_config.json"

# ------------------------------------------------------------------ 配色
BG = "#f4f5f7"
CARD = "#ffffff"
BORDER = "#d8dde3"
TEXT = "#1f2328"
MUTED = "#6b7480"
INPUT_BG = "#fbfcfd"
ACCENT = "#2f7d5b"
ACCENT_ACTIVE = "#276a4c"
STOP_RED = "#b3423a"
STOP_RED_ACTIVE = "#963631"
LOG_BG = "#1c1c1c"
LOG_DEFAULT = "#d6d6d6"

LOG_COLORS = {
    forwarder.L_SYS: "#8fb3d9",    # 系统/连接
    forwarder.L_REQ: "#4ec9b0",    # 设备请求
    forwarder.L_RESP: "#7cb7e8",   # 服务器响应
    forwarder.L_HEAD: "#9a9a9a",   # 头部明细
    forwarder.L_BODY: "#e4e4e4",   # 文本正文
    forwarder.L_BIN: "#d7ba7d",    # 二进制说明
    forwarder.L_OK: "#89d185",     # 耗时/成功
    forwarder.L_ERR: "#f26b5e",    # 错误
    forwarder.L_WARN: "#e0c36b",   # 警告
}

MAX_LOG_LINES = 4000

# 日志文件：运行目录下的 logs 子目录，按日期分文件、同一天追加
LOG_DIR_NAME = "logs"
LOG_FILE_PREFIX = "HTTP转发服务-"


# ------------------------------------------------------------------ 工具函数
def app_dir() -> str:
    """程序所在目录；打包成 exe 后指向 exe 目录。"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return BASE_DIR


def resource_path(name: str) -> str:
    """打包后资源在临时解包目录里，未打包时在源码目录。"""
    base = getattr(sys, "_MEIPASS", BASE_DIR)
    return os.path.join(base, name)


def config_path() -> str:
    """配置文件路径：优先放在程序目录，不可写时退到 %APPDATA%。"""
    primary = os.path.join(app_dir(), CONFIG_NAME)
    primary_dir = os.path.dirname(primary)
    writable = os.access(primary_dir, os.W_OK) if os.path.isdir(primary_dir) else False
    if not writable:
        fallback_dir = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "HTTPForwarder")
        try:
            os.makedirs(fallback_dir, exist_ok=True)
        except OSError:
            return primary
        return os.path.join(fallback_dir, CONFIG_NAME)
    return primary


def local_ipv4_list() -> list[str]:
    """取本机局域网 IPv4。默认出口网卡排最前——设备大概率就在这个网段。"""
    primary = None
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.settimeout(0.3)
        probe.connect(("8.8.8.8", 53))
        primary = probe.getsockname()[0]
        probe.close()
    except OSError:
        primary = None

    ips: list[str] = []
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, 0, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except OSError:
        pass

    ips = [ip for ip in ips if not ip.startswith(("127.", "169.254."))]
    if primary and not primary.startswith(("127.", "169.254.")):
        ips = [primary] + [ip for ip in ips if ip != primary]
    return ips or ["127.0.0.1"]


# ------------------------------------------------------------------ 主窗口
class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.proxy = None
        self.running = False
        self._q: queue.Queue = queue.Queue()
        self._line_check_counter = 0
        self.var_pause = tk.BooleanVar(value=False)
        self.paused_skipped = 0
        # 日志文件（与界面显示互不影响：暂停/清空界面时文件照常写）
        self._log_lock = threading.Lock()
        self._log_fh = None
        self._log_date = ""
        self._log_path = ""
        self._log_error = ""
        self._log_error_reported = False

        root.title(APP_TITLE)
        root.geometry("1200x780")
        root.minsize(960, 600)
        root.configure(bg=BG)
        self._set_window_icon()

        self._build_style()
        self._build_ui()
        self._load_config()
        self._update_title()

        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(60, self._poll_queue)

    # -------------------------------------------------- 样式
    def _set_window_icon(self) -> None:
        ico = resource_path("app_icon.ico")
        if os.path.exists(ico):
            try:
                self.root.iconbitmap(ico)
            except tk.TclError:
                pass

    def _build_style(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "TCombobox",
            fieldbackground="#ffffff",
            background="#ffffff",
            foreground=TEXT,
            arrowcolor="#5b6570",
            bordercolor=BORDER,
            lightcolor=BORDER,
            darkcolor=BORDER,
            padding=3,
        )
        style.configure(
            "Dark.Vertical.TScrollbar",
            background="#3c3c3c",
            troughcolor="#222222",
            bordercolor="#222222",
            darkcolor="#3c3c3c",
            lightcolor="#3c3c3c",
            arrowcolor="#9a9a9a",
        )
        style.map(
            "Dark.Vertical.TScrollbar",
            background=[("active", "#4d4d4d"), ("pressed", "#565656")],
        )

    # -------------------------------------------------- 界面
    def _build_ui(self) -> None:
        outer = tk.Frame(self.root, bg=BG)
        outer.pack(fill="both", expand=True, padx=14, pady=12)

        # 标题
        head = tk.Frame(outer, bg=BG)
        head.pack(fill="x")
        tk.Label(
            head, text="HTTP 转发抓包服务", bg=BG, fg=TEXT,
            font=("Microsoft YaHei UI", 15, "bold"),
        ).pack(side="left")
        tk.Label(
            head, text="设备 → 本机转发 → 远程服务器，全程记录请求与响应", bg=BG, fg=MUTED,
            font=("Microsoft YaHei UI", 9),
        ).pack(side="left", padx=(12, 0), pady=(6, 0))

        # 配置卡片
        card = tk.Frame(outer, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", pady=(10, 10))

        body = tk.Frame(card, bg=CARD)
        body.pack(fill="x", padx=16, pady=(14, 10))

        self.var_port = tk.StringVar(value="8089")
        self.var_protocol = tk.StringVar(value="http")
        self.var_host = tk.StringVar(value="")
        self.var_rport = tk.StringVar(value="80")

        # 1) 本地监听端口
        box1 = tk.Frame(body, bg=CARD)
        box1.grid(row=0, column=0, sticky="ew", padx=(0, 18))
        tk.Label(box1, text="本地监听端口（设备连接本机）", bg=CARD, fg=MUTED,
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w")
        self.entry_port = self._entry(box1, self.var_port, width=12)
        self.entry_port.pack(fill="x", pady=(4, 0))

        # 2) 协议
        box2 = tk.Frame(body, bg=CARD)
        box2.grid(row=0, column=1, sticky="ew", padx=(0, 18))
        tk.Label(box2, text="远端协议", bg=CARD, fg=MUTED,
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w")
        proto_row = tk.Frame(box2, bg=CARD)
        proto_row.pack(fill="x", pady=(6, 0))
        self.radio_http = tk.Radiobutton(
            proto_row, text="http", variable=self.var_protocol, value="http",
            bg=CARD, fg=TEXT, activebackground=CARD, selectcolor="#ffffff",
            font=("Microsoft YaHei UI", 10), anchor="w", cursor="hand2",
        )
        self.radio_http.pack(side="left")
        self.radio_https = tk.Radiobutton(
            proto_row, text="https", variable=self.var_protocol, value="https",
            bg=CARD, fg=TEXT, activebackground=CARD, selectcolor="#ffffff",
            font=("Microsoft YaHei UI", 10), anchor="w", cursor="hand2",
        )
        self.radio_https.pack(side="left", padx=(10, 0))

        # 3) 远程服务地址
        box3 = tk.Frame(body, bg=CARD)
        box3.grid(row=0, column=2, sticky="ew", padx=(0, 18))
        tk.Label(box3, text="远程服务地址（IP 或域名）", bg=CARD, fg=MUTED,
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w")
        self.entry_host = self._entry(box3, self.var_host, width=28)
        self.entry_host.pack(fill="x", pady=(4, 0))

        # 4) 远程服务端口
        box4 = tk.Frame(body, bg=CARD)
        box4.grid(row=0, column=3, sticky="ew")
        tk.Label(box4, text="远程服务端口", bg=CARD, fg=MUTED,
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w")
        self.entry_rport = self._entry(box4, self.var_rport, width=12)
        self.entry_rport.pack(fill="x", pady=(4, 0))

        body.columnconfigure(0, weight=0, minsize=150)
        body.columnconfigure(1, weight=0, minsize=120)
        body.columnconfigure(2, weight=1)
        body.columnconfigure(3, weight=0, minsize=110)

        self._inputs = [self.entry_port, self.entry_host, self.entry_rport]

        # 按钮行
        btns = tk.Frame(card, bg=CARD)
        btns.pack(fill="x", padx=16, pady=(2, 14))

        self.btn_start = self._button(btns, "启动服务", ACCENT, ACCENT_ACTIVE, "#ffffff",
                                      self._on_start, width=12)
        self.btn_start.pack(side="left")
        self.btn_stop = self._button(btns, "停止服务", STOP_RED, STOP_RED_ACTIVE, "#ffffff",
                                     self._on_stop, width=12)
        self.btn_stop.pack(side="left", padx=(10, 0))
        self.btn_stop.configure(state="disabled")

        self.btn_clear = self._button(btns, "清空日志", "#eef0f3", "#e2e5ea", TEXT,
                                      self._on_clear, width=10)
        self.btn_clear.pack(side="left", padx=(10, 0))
        self.btn_export = self._button(btns, "导出日志", "#eef0f3", "#e2e5ea", TEXT,
                                       self._on_export, width=10)
        self.btn_export.pack(side="left", padx=(10, 0))

        self.chk_pause = tk.Checkbutton(
            btns, text="暂停日志输出", variable=self.var_pause, command=self._on_pause_toggle,
            bg=CARD, fg=TEXT, activebackground=CARD, activeforeground=TEXT,
            selectcolor="#ffffff", font=("Microsoft YaHei UI", 9),
            cursor="hand2", bd=0, highlightthickness=0, padx=2,
        )
        self.chk_pause.pack(side="left", padx=(14, 0))

        self.lbl_hint = tk.Label(
            btns, text="", bg=CARD, fg=MUTED, font=("Microsoft YaHei UI", 9), anchor="e",
        )
        self.lbl_hint.pack(side="right")

        # 日志区
        log_wrap = tk.Frame(outer, bg=LOG_BG, highlightbackground="#0f0f0f", highlightthickness=1)
        log_wrap.pack(fill="both", expand=True)

        log_head = tk.Frame(log_wrap, bg="#232323")
        log_head.pack(fill="x")
        tk.Label(log_head, text="实时日志", bg="#232323", fg="#a9a9a9",
                 font=("Microsoft YaHei UI", 9)).pack(side="left", padx=(12, 0), pady=6)
        self.lbl_log_state = tk.Label(log_head, text="", bg="#232323", fg="#e0b654",
                                      font=("Microsoft YaHei UI", 9, "bold"))
        self.lbl_log_state.pack(side="left", padx=(8, 0), pady=6)
        tk.Label(log_head, text="蓝=系统 · 青=设备请求 · 浅蓝=服务器响应 · 黄=文件/二进制 · 绿=耗时 · 红=错误",
                 bg="#232323", fg="#7d7d7d", font=("Microsoft YaHei UI", 9)).pack(side="right", padx=12)

        text_area = tk.Frame(log_wrap, bg=LOG_BG)
        text_area.pack(fill="both", expand=True)

        self.txt = tk.Text(
            text_area, bg=LOG_BG, fg=LOG_DEFAULT, relief="flat", borderwidth=0,
            font=("Consolas", 10), padx=12, pady=8, insertwidth=0,
            selectbackground="#2a4a63", wrap="word", state="disabled",
            spacing1=1, spacing3=1,
        )
        scroll = ttk.Scrollbar(text_area, orient="vertical", command=self.txt.yview,
                               style="Dark.Vertical.TScrollbar")
        self.txt.configure(yscrollcommand=scroll.set)
        self.txt.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.txt.tag_configure("time", foreground="#7ec8f0")
        for level, color in LOG_COLORS.items():
            self.txt.tag_configure(level, foreground=color)

        # 状态栏
        status = tk.Frame(outer, bg=BG)
        status.pack(fill="x", pady=(8, 0))
        self.dot = tk.Label(status, text="●", bg=BG, fg="#9aa4af", font=("Segoe UI", 11))
        self.dot.pack(side="left")
        self.lbl_status = tk.Label(status, text="未启动", bg=BG, fg=TEXT,
                                   font=("Microsoft YaHei UI", 9))
        self.lbl_status.pack(side="left", padx=(4, 0))
        self.lbl_count = tk.Label(status, text="已处理请求：0", bg=BG, fg=MUTED,
                                  font=("Microsoft YaHei UI", 9))
        self.lbl_count.pack(side="right")

        self.var_protocol.trace_add("write", self._on_protocol_change)
        self.entry_port.focus_set()

    def _entry(self, parent, var: tk.StringVar, width: int) -> tk.Entry:
        return tk.Entry(
            parent, textvariable=var, width=width, relief="flat",
            bg=INPUT_BG, fg=TEXT, insertbackground=TEXT,
            disabledbackground="#f0f0f0", disabledforeground="#8a929c",
            highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT,
            font=("Consolas", 10),
        )

    def _button(self, parent, text, bg, active_bg, fg, command, width) -> tk.Button:
        return tk.Button(
            parent, text=text, command=command, width=width,
            bg=bg, fg=fg, activebackground=active_bg, activeforeground=fg,
            disabledforeground="#b9c0c8", relief="flat", borderwidth=0,
            font=("Microsoft YaHei UI", 10), cursor="hand2", pady=6,
        )

    # -------------------------------------------------- 协议联动端口
    def _on_protocol_change(self, *_) -> None:
        proto = self.var_protocol.get()
        rport = self.var_rport.get().strip()
        if proto == "https" and rport in ("", "80"):
            self.var_rport.set("443")
        elif proto == "http" and rport in ("", "443"):
            self.var_rport.set("80")

    # -------------------------------------------------- 配置读写
    def _load_config(self) -> None:
        path = config_path()
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except (OSError, ValueError):
            cfg = {}
        if isinstance(cfg, dict):
            port = cfg.get("listen_port", 8089)
            self.var_port.set(str(port))
            proto = str(cfg.get("protocol", "http")).lower()
            self.var_protocol.set(proto if proto in ("http", "https") else "http")
            self.var_host.set(str(cfg.get("remote_host", "")))
            rport = cfg.get("remote_port", 443 if self.var_protocol.get() == "https" else 80)
            self.var_rport.set(str(rport))
        self._update_hint()

    def _save_config(self, cfg: dict | None = None) -> None:
        if cfg is None:
            cfg = self._read_form(silent=True)
            if cfg is None:
                return
        cfg["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(config_path(), "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
        except OSError as exc:
            self._log(forwarder.L_WARN, f"保存配置失败：{exc}")

    def _read_form(self, silent: bool = False) -> dict | None:
        port_text = self.var_port.get().strip()
        if not port_text.isdigit() or not (1 <= int(port_text) <= 65535):
            if not silent:
                messagebox.showwarning(APP_TITLE, "本地监听端口必须是 1~65535 之间的数字。", parent=self.root)
                self.entry_port.focus_set()
            return None
        host = self.var_host.get().strip()
        if not host:
            if not silent:
                messagebox.showwarning(APP_TITLE, "请填写远程服务地址（服务器的 IP 或域名）。", parent=self.root)
                self.entry_host.focus_set()
            return None
        rport_text = self.var_rport.get().strip()
        if not rport_text.isdigit() or not (1 <= int(rport_text) <= 65535):
            if not silent:
                messagebox.showwarning(APP_TITLE, "远程服务端口必须是 1~65535 之间的数字。", parent=self.root)
                self.entry_rport.focus_set()
            return None
        return {
            "listen_port": int(port_text),
            "protocol": self.var_protocol.get(),
            "remote_host": host,
            "remote_port": int(rport_text),
        }

    # -------------------------------------------------- 启动 / 停止
    def _on_start(self) -> None:
        if self.running:
            return
        cfg = self._read_form()
        if cfg is None:
            return
        self._save_config(cfg)

        try:
            self.proxy = forwarder.ProxyServer(cfg, self._log)
            self.proxy.start()
        except OSError as exc:
            self.proxy = None
            self._log(forwarder.L_ERR, f"监听端口 {cfg['listen_port']} 失败：{exc}")
            messagebox.showerror(
                APP_TITLE,
                f"无法在端口 {cfg['listen_port']} 上启动服务。\n\n{exc}\n\n"
                "常见原因：端口已被其它程序占用，或权限不足。",
                parent=self.root,
            )
            return

        target = f"{cfg['protocol']}://{cfg['remote_host']}:{cfg['remote_port']}"
        ips = local_ipv4_list()
        self._log(forwarder.L_OK, f"服务已启动 · 监听 0.0.0.0:{cfg['listen_port']} → {target}")
        self._log(forwarder.L_SYS, f"设备请连接 http://{ips[0]}:{cfg['listen_port']} · 连接超时 15 秒 / 响应超时 60 秒")
        if cfg["protocol"] == "https":
            self._log(forwarder.L_WARN, "https 转发已跳过证书校验，自签名证书服务器也能转发")
        self._log(forwarder.L_HEAD, "配置已保存：" + config_path())

        self._set_running(True)
        self._update_hint()

    def _on_stop(self) -> None:
        if not self.running or self.proxy is None:
            return
        self.proxy.stop()
        self.proxy = None
        self._set_running(False)
        self._update_hint()
        self._log(forwarder.L_WARN, "服务已停止，不再接受新连接")

    def _set_running(self, running: bool) -> None:
        self.running = running
        state = "disabled" if running else "normal"
        for widget in self._inputs:
            widget.configure(state=state)
        self.radio_http.configure(state=state)
        self.radio_https.configure(state=state)
        self.btn_start.configure(state="disabled" if running else "normal",
                                 bg="#c3d5cb" if running else ACCENT,
                                 cursor="arrow" if running else "hand2")
        self.btn_stop.configure(state="normal" if running else "disabled",
                                bg=STOP_RED if running else "#e6cfcd",
                                cursor="hand2" if running else "arrow")
        self.dot.configure(fg="#2f9e60" if running else "#9aa4af")
        if running and self.proxy:
            self.lbl_status.configure(text=f"运行中 · 0.0.0.0:{self.proxy.listen_port}")
        else:
            self.lbl_status.configure(text="未启动")

    def _update_hint(self) -> None:
        if self.running and self.proxy:
            ips = local_ipv4_list()
            self.lbl_hint.configure(
                text=f"设备请连接：http://{ips[0]}:{self.proxy.listen_port}  →  "
                     f"{self.proxy.protocol}://{self.proxy.remote_host}:{self.proxy.remote_port}"
            )
        else:
            proto = self.var_protocol.get()
            host = self.var_host.get().strip() or "<服务器IP>"
            self.lbl_hint.configure(
                text=f"转发规则：设备 → 本机 {self.var_port.get() or '8089'}  →  {proto}://{host}:{self.var_rport.get() or '?'}"
            )
        self._update_title()

    def _update_title(self) -> None:
        """标题栏显示本机 IP，运行中再带上监听端口。"""
        try:
            ip = local_ipv4_list()[0]
        except Exception:
            ip = "?"
        port = self.proxy.listen_port if (self.running and self.proxy) else self.var_port.get().strip()
        if not port:
            port = "8089"
        prefix = "监听中" if self.running else "本机"
        self.root.title(f"{APP_TITLE} —— {prefix} {ip}:{port}")

    # -------------------------------------------------- 日志
    def _log(self, level: str, text: str, with_time: bool = True) -> None:
        """可在任意线程调用：先落盘（不受暂停/清空影响），再进队列给界面。"""
        ts = self._stamp() if with_time else ""
        self._write_log_file(ts, text)
        self._q.put((level, text, ts))

    @staticmethod
    def _stamp() -> str:
        """时间戳格式 15:51:55.278（时:分:秒.毫秒），与抓包工具的写法一致。"""
        now = datetime.now()
        return now.strftime("%H:%M:%S.") + f"{now.microsecond // 1000:03d}"

    # -------------------------------------------------- 日志文件
    def _log_dir(self) -> str:
        return os.path.join(app_dir(), LOG_DIR_NAME)

    def _log_file_path_today(self) -> str:
        return os.path.join(self._log_dir(), LOG_FILE_PREFIX + datetime.now().strftime("%Y-%m-%d") + ".log")

    def _ensure_log_file(self) -> None:
        """按日期打开日志文件；跨天自动换新文件，同一天继续追加。"""
        today = datetime.now().strftime("%Y-%m-%d")
        if self._log_fh is not None and not self._log_fh.closed and self._log_date == today:
            return
        try:
            os.makedirs(self._log_dir(), exist_ok=True)
            path = self._log_file_path_today()
            is_new = not os.path.exists(path)
            # 行缓冲 + 自带 \r\n：记事本直接打开也不会乱行
            fh = open(path, "a", encoding="utf-8", buffering=1, newline="")
            if is_new:
                fh.write("\ufeff")  # 带 BOM，Win7 记事本也能正确显示中文
            self._log_fh = fh
            self._log_date = today
            self._log_path = path
            self._log_error = ""
        except OSError as exc:
            self._log_fh = None
            self._log_error = str(exc)

    def _write_log_file(self, ts: str, text: str) -> None:
        with self._log_lock:
            self._ensure_log_file()
            if self._log_fh is None:
                return
            try:
                self._log_fh.write((f"[{ts}] {text}" if ts else text) + "\r\n")
            except (OSError, ValueError) as exc:
                self._log_error = str(exc)
                try:
                    self._log_fh.close()
                except OSError:
                    pass
                self._log_fh = None

    def _close_log_file(self) -> None:
        with self._log_lock:
            if self._log_fh is not None:
                try:
                    self._log_fh.close()
                except OSError:
                    pass
                self._log_fh = None

    def log_file_hint(self) -> str:
        """给界面用的一行说明：日志文件在哪。"""
        if self._log_fh is not None and self._log_path:
            return "日志文件：" + os.path.relpath(self._log_path, app_dir()).replace("/", "\\") + \
                   "（界面暂停或清空时仍继续写入）"
        return f"日志文件写入失败：{self._log_error or '目录不可写'}（日志只显示在界面）"

    def _poll_queue(self) -> None:
        items = []
        try:
            while len(items) < 500:
                items.append(self._q.get_nowait())
        except queue.Empty:
            pass
        if items:
            if self.var_pause.get():
                # 暂停期间照常从队列取走（避免积压），只是不再写进日志框；文件已照常落盘
                self.paused_skipped += len(items)
            else:
                self._append_items(items)
        if self._log_error and not self._log_error_reported:
            self._log_error_reported = True
            self._append_items([
                (forwarder.L_ERR, f"日志文件写入失败：{self._log_error}（日志只显示在界面）", self._stamp())
            ])
        if self.running and self.proxy:
            self.lbl_count.configure(text=f"已处理请求：{self.proxy.request_count}")
        self.root.after(60, self._poll_queue)

    def _append_items(self, items) -> None:
        self.txt.configure(state="normal")
        for level, text, ts in items:
            if ts:
                self.txt.insert("end", f"[{ts}] ", ("time",))
            self.txt.insert("end", text + "\n", (level,))
        self.txt.configure(state="disabled")
        self.txt.see("end")

        self._line_check_counter += 1
        if self._line_check_counter >= 10:
            self._line_check_counter = 0
            total = int(self.txt.index("end-1c").split(".")[0])
            if total > MAX_LOG_LINES:
                self.txt.configure(state="normal")
                self.txt.delete("1.0", f"{total - MAX_LOG_LINES}.0")
                self.txt.configure(state="disabled")

    def _on_pause_toggle(self) -> None:
        """暂停日志输出：停止往日志框追加，方便停下来翻看已有流量。"""
        if self.var_pause.get():
            self.lbl_log_state.configure(text="● 已暂停接收", fg="#e0b654")
        else:
            self.lbl_log_state.configure(text="")
            skipped = self.paused_skipped
            self.paused_skipped = 0
            note = f"，暂停期间有 {skipped} 条日志未显示（均已写入日志文件）" if skipped else ""
            self._log(forwarder.L_WARN, f"已恢复日志输出{note}")

    def _on_clear(self) -> None:
        self.txt.configure(state="normal")
        self.txt.delete("1.0", "end")
        self.txt.configure(state="disabled")
        self._log(forwarder.L_SYS, "日志已清空（仅清界面，日志文件继续保留在 logs 目录）")

    def _on_export(self) -> None:
        default_name = f"转发日志-{datetime.now():%Y%m%d-%H%M%S}.txt"
        path = filedialog.asksaveasfilename(
            parent=self.root, title="导出日志", initialdir=app_dir(),
            initialfile=default_name, defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.txt.get("1.0", "end-1c"))
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"保存失败：{exc}", parent=self.root)
            return
        self._log(forwarder.L_OK, f"日志已导出到 {path}")

    # -------------------------------------------------- 关闭
    def _on_close(self) -> None:
        self._save_config()
        if self.proxy is not None:
            self.proxy.stop()
            self.proxy = None
        self._close_log_file()
        self.root.destroy()


def _enable_dpi_awareness() -> None:
    """高分屏下避免界面被系统拉伸变糊（Win7 上自动跳过）。"""
    try:
        from ctypes import windll
        try:
            windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def main() -> None:
    _enable_dpi_awareness()
    root = tk.Tk()
    app = App(root)
    app._log(
        forwarder.L_SYS,
        "程序已启动。填写远端协议/地址/端口后点击“启动服务”；"
        "设备把 http 服务地址指向本机 IP、端口填本机监听端口即可。",
    )
    app._log(forwarder.L_SYS, app.log_file_hint())
    root.mainloop()


if __name__ == "__main__":
    main()
