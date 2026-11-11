# -*- coding: utf-8 -*-
"""HTTP 转发抓包核心模块（与界面无关）。

工作方式：
    设备  --HTTP-->  本程序(监听端口)  --HTTP/HTTPS-->  远程服务器
    服务器响应再原路回给设备，全程记录请求/响应的每一行头与正文。

只依赖标准库，方便打包成 exe。
"""

from __future__ import annotations

import gzip
import socket
import ssl
import threading
import time
import zlib
from dataclasses import dataclass
from typing import Callable, List, Tuple, Optional

# ---------------------------------------------------------------- 日志级别
L_SYS = "sys"      # 系统状态（启动、连接建立/断开）
L_REQ = "req"      # 设备 -> 服务器 请求
L_RESP = "resp"    # 服务器 -> 设备 响应
L_HEAD = "head"    # 头部明细
L_BODY = "body"    # 文本正文
L_BIN = "bin"      # 二进制说明
L_OK = "ok"        # 耗时 / 成功
L_ERR = "err"      # 错误
L_WARN = "warn"    # 警告

MAX_TEXT_CHARS = 6000        # 单段文本正文最多输出字符数，超出截断
CLIENT_IDLE_TIMEOUT = 60.0   # 设备侧空闲多久关闭连接（秒）
CONNECT_TIMEOUT = 15.0       # 连接远程服务器超时（秒）
RESPONSE_TIMEOUT = 60.0      # 等待/读取远程响应超时（秒）

# 逐跳头，转发时不能原样带给目标服务器
HOP_BY_HOP = {
    "connection", "proxy-connection", "keep-alive", "transfer-encoding",
    "upgrade", "te", "trailer", "proxy-authenticate", "proxy-authorization",
}


# ------------------------------------------------------------------ 数据结构
@dataclass
class Request:
    method: str
    path: str
    version: str
    headers: List[Tuple[str, str]]
    body: bytes
    peer: str
    keep_alive: bool
    received_at: float = 0.0   # 请求行到达的时刻，用于计算本次请求总耗时

    def header(self, name: str) -> str:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return ""


@dataclass
class Response:
    status_line: str
    code: int
    reason: str
    headers: List[Tuple[str, str]]
    body: bytes
    raw_length: int = 0
    head_wait: float = 0.0     # 从发出请求到收到响应头（秒）
    total_wait: float = 0.0    # 从发出请求到收完响应体（秒）

    def header(self, name: str) -> str:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return ""


# ------------------------------------------------------------------ 读取器
class _Reader:
    """带缓冲的 socket 读取器，支持按行/按长度读取。"""

    __slots__ = ("sock", "buf", "eof")

    def __init__(self, sock: socket.socket, initial: bytes = b""):
        self.sock = sock
        self.buf = bytearray(initial)
        self.eof = False

    def _fill(self) -> None:
        data = self.sock.recv(65536)
        if data:
            self.buf += data
        else:
            self.eof = True

    def read_line(self) -> bytes:
        while True:
            idx = self.buf.find(b"\r\n")
            if idx >= 0:
                end = idx + 2
                out = bytes(self.buf[:end])
                del self.buf[:end]
                return out
            if self.eof:
                out = bytes(self.buf)
                self.buf.clear()
                return out
            self._fill()

    def read_exact(self, n: int) -> bytes:
        while len(self.buf) < n and not self.eof:
            self._fill()
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def read_all(self) -> bytes:
        while not self.eof:
            self._fill()
        out = bytes(self.buf)
        self.buf.clear()
        return out


def _read_chunked(reader: _Reader) -> bytes:
    """读取 Transfer-Encoding: chunked 的正文，返回解码后的完整字节。"""
    body = bytearray()
    while True:
        line = reader.read_line()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            size = int(line.split(b";")[0].strip(), 16)
        except ValueError:
            break
        if size == 0:
            # 读掉 trailer 直到空行
            while True:
                trailer = reader.read_line()
                if not trailer or trailer in (b"\r\n", b"\n"):
                    break
            break
        body += reader.read_exact(size)
        reader.read_exact(2)  # 分块后面的 CRLF
    return bytes(body)


# ------------------------------------------------------------------ 内容识别
_TEXT_CONTROL = set(range(0, 9)) | set(range(14, 32)) | {127}


def _is_binary(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    if b"\x00" in sample:
        return True
    ctrl = sum(1 for b in sample if b in _TEXT_CONTROL)
    return (ctrl / len(sample)) > 0.05


def _decode_text(data: bytes, charset: str | None = None) -> Optional[Tuple[str, str]]:
    """尝试把字节解码为文本，成功返回 (文本, 编码名)，失败返回 None。"""
    declared = None
    if charset:
        charset = charset.strip().strip('"\'').lower()
        if charset in ("utf8", "utf-8"):
            declared = "utf-8"
        elif charset in ("gbk", "gb2312", "gb18030"):
            declared = "gb18030"
        else:
            declared = charset
    # 先按 UTF-8 严格解码：有些国产服务器声明 gb2312/GBK，实际发的是 UTF-8，
    # 直接照声明解会整段中文乱码；真正的 GB 编码内容 UTF-8 解码必然失败，不会被误判。
    candidates = ["utf-8"]
    if declared and declared not in candidates:
        candidates.append(declared)
    if "gb18030" not in candidates:
        candidates.append("gb18030")
    for enc in candidates:
        try:
            text = data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        if any(ch in text for ch in "\x00") or not text:
            if not text:
                return "", enc
            continue
        bad = sum(1 for ch in text if ord(ch) in _TEXT_CONTROL)
        if bad / max(1, len(text)) > 0.03:
            continue
        return text, enc
    return None


_CTYPE_DESC = {
    "application/json": "JSON 数据",
    "application/xml": "XML 数据",
    "text/xml": "XML 数据",
    "application/octet-stream": "二进制数据",
    "application/pdf": "PDF 文档",
    "application/zip": "ZIP 压缩包",
    "application/x-rar-compressed": "RAR 压缩包",
    "image/jpeg": "JPEG 图片",
    "image/png": "PNG 图片",
    "image/gif": "GIF 图片",
    "image/bmp": "BMP 图片",
    "image/webp": "WEBP 图片",
    "audio/mpeg": "MP3 音频",
    "audio/wav": "WAV 音频",
    "video/mp4": "MP4 视频",
    "multipart/form-data": "表单(可能含文件)",
}


def _sniff(data: bytes) -> str:
    """按文件头判断二进制内容类型。"""
    head = data[:16]
    if head[:2] == b"\xff\xd8":
        return "JPEG 图片"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG 图片"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "GIF 图片"
    if head[:4] == b"%PDF":
        return "PDF 文档"
    if head[:4] == b"PK\x03\x04":
        return "ZIP/APK/Office 压缩包"
    if head[:4] == b"Rar!":
        return "RAR 压缩包"
    if head[:4] == b"\x1f\x8b":
        return "GZIP 压缩数据"
    if head[:2] == b"BM":
        return "BMP 图片"
    if head[:4] == b"RIFF":
        sub = data[8:12]
        if sub == b"WEBP":
            return "WEBP 图片"
        if sub == b"WAVE":
            return "WAV 音频"
        return "RIFF 媒体文件"
    if head[4:8] == b"ftyp":
        return "MP4/HEIC 视频或图片"
    if head[:4] == b"\xd0\xcf\x11\xe0":
        return "旧版 Office 文档(doc/xls)"
    if head[:3] == b"ID3" or head[:2] == b"\xff\xfb":
        return "MP3 音频"
    if head[:4] == b"fLaC":
        return "FLAC 音频"
    if head[:4] == b"OggS":
        return "OGG 音频"
    if head[:4] == b"\x7fELF":
        return "ELF 可执行文件"
    if head[:2] == b"MZ":
        return "Windows 程序文件"
    if head[:3] == b"\xef\xbb\xbf":
        return "UTF-8 BOM 文本"
    return "未知二进制"


def _describe(data: bytes, ctype: str) -> str:
    """优先按文件头判断，其次按 Content-Type。"""
    sniffed = _sniff(data)
    if sniffed != "未知二进制":
        return sniffed
    if ctype:
        base = ctype.split(";")[0].strip().lower()
        return _CTYPE_DESC.get(base, ctype)
    return sniffed


def _charset_of(ctype: str) -> Optional[str]:
    for part in ctype.split(";")[1:]:
        part = part.strip()
        if part.lower().startswith("charset="):
            return part.split("=", 1)[1]
    return None


def _decompress(data: bytes, content_encoding: str) -> bytes:
    """只为日志展示解压（发送给设备的仍是原始字节）。"""
    enc = (content_encoding or "").lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(data)
        if "deflate" in enc:
            try:
                return zlib.decompress(data)
            except zlib.error:
                return zlib.decompress(data, -zlib.MAX_WBITS)
    except Exception:
        return data
    return data


# ------------------------------------------------------------------ 转发服务
class ProxyServer:
    """监听本地端口，把设备请求转发到远程服务并记录全过程。"""

    def __init__(self, cfg: dict, log: Callable[..., None]):
        self.listen_port = int(cfg["listen_port"])
        self.protocol = (cfg.get("protocol") or "http").strip().lower()
        if self.protocol not in ("http", "https"):
            self.protocol = "http"
        self.remote_host = (cfg.get("remote_host") or "").strip()
        self.remote_port = int(cfg["remote_port"])
        self.log = log
        self.request_count = 0

        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._count_lock = threading.Lock()

    # -------------------------------------------------- 生命周期
    def start(self) -> None:
        """绑定并开始监听；端口被占用等错误以 OSError 抛出。"""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind(("0.0.0.0", self.listen_port))
            self._sock.listen(128)
        except OSError:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
            raise
        self._sock.settimeout(0.5)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, name="accept", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        sock = self._sock
        self._sock = None
        if sock:
            try:
                sock.close()
            except OSError:
                pass
        thread = self._thread
        self._thread = None
        if thread:
            thread.join(timeout=1.5)

    @property
    def running(self) -> bool:
        return self._running

    def target_desc(self, path: str = "") -> str:
        return f"{self.protocol}://{self.remote_host}:{self.remote_port}{path}"

    # -------------------------------------------------- 接受连接
    def _accept_loop(self) -> None:
        while self._running:
            sock = self._sock
            if sock is None:
                break
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._running:
                try:
                    conn.close()
                except OSError:
                    pass
                break
            threading.Thread(
                target=self._handle_client, args=(conn, addr), name="client", daemon=True
            ).start()

    def _emit(self, level: str, text: str, with_time: bool = True) -> None:
        try:
            self.log(level, text, with_time)
        except Exception:
            pass

    # -------------------------------------------------- 单个连接
    def _handle_client(self, conn: socket.socket, addr) -> None:
        peer = f"{addr[0]}:{addr[1]}"
        self._emit(L_SYS, f"设备 {peer} 已连接")
        conn.settimeout(CLIENT_IDLE_TIMEOUT)
        reader = _Reader(conn)
        req_no = 0
        try:
            while self._running:
                try:
                    req = self._read_request(reader, peer)
                except socket.timeout:
                    self._emit(L_WARN, f"设备 {peer} 空闲超过 {int(CLIENT_IDLE_TIMEOUT)} 秒，关闭连接")
                    break
                except Exception as exc:
                    self._emit(L_ERR, f"读取设备 {peer} 的请求失败：{exc}")
                    break
                if req is None:
                    self._emit(L_SYS, f"设备 {peer} 已断开")
                    break

                req_no += 1
                with self._count_lock:
                    self.request_count += 1
                    total = self.request_count

                self._log_request(req, total)

                t_fwd = time.perf_counter()
                try:
                    resp = self._forward(req)
                except Exception as exc:
                    why = (f"超时（连接 {CONNECT_TIMEOUT} 秒 / 响应 {RESPONSE_TIMEOUT} 秒）"
                           if isinstance(exc, socket.timeout) else str(exc))
                    self._emit(L_ERR, f"转发到 {self.target_desc()} 失败：{why}")
                    self._send_error(conn, req, 502, f"转发失败：{why}")
                    # 设备收到的是这个错误响应，日志里也要能看到我们回了什么
                    self._emit(L_ERR, f"返回给设备 {peer}：HTTP/1.1 502 Bad Gateway（转发失败，{why}）")
                    self._emit(L_BODY, "", with_time=False)
                    break
                t_resp = time.perf_counter()

                self._log_response(resp)

                try:
                    self._send_response(conn, req, resp)
                except Exception as exc:
                    self._emit(L_ERR, f"回写给设备 {peer} 失败：{exc}")
                    break
                t_end = time.perf_counter()

                total_ms = (t_end - req.received_at) * 1000
                forward_ms = (t_resp - t_fwd) * 1000
                self._emit(
                    L_OK,
                    f"耗时 {total_ms:.0f} ms（服务器往返 {forward_ms:.0f} ms）"
                    f" · 上传 {len(req.body)} 字节 / 下载 {len(resp.body)} 字节",
                )
                # 与下一笔请求之间留一空行
                self._emit(L_BODY, "", with_time=False)

                if not req.keep_alive:
                    break
        finally:
            try:
                conn.close()
            except OSError:
                pass

    # -------------------------------------------------- 解析请求
    def _read_request(self, reader: _Reader, peer: str) -> Optional[Request]:
        # 跳过请求行之前的空行（部分设备会多发 CRLF）
        while True:
            line = reader.read_line()
            if not line:
                return None
            if line in (b"\r\n", b"\n"):
                continue
            break

        request_line = line.decode("latin-1").rstrip("\r\n")
        t_received = time.perf_counter()
        parts = request_line.split()
        if len(parts) < 2:
            raise ValueError(f"无法解析请求行：{request_line!r}")
        method = parts[0]
        path = parts[1]
        version = parts[2] if len(parts) > 2 else "HTTP/1.0"

        headers: List[Tuple[str, str]] = []
        while True:
            raw = reader.read_line()
            if not raw:
                raise ConnectionError("请求头未结束连接就断开了")
            if raw in (b"\r\n", b"\n"):
                break
            text = raw.decode("latin-1").rstrip("\r\n")
            if text[:1] in (" ", "\t") and headers:
                # 头部折行
                name, value = headers[-1]
                headers[-1] = (name, value + " " + text.strip())
                continue
            name, sep, value = text.partition(":")
            if not sep:
                raise ValueError(f"无法解析请求头：{text!r}")
            headers.append((name.strip(), value.strip()))

        # 正文长度
        te = ""
        cl = ""
        for k, v in headers:
            low = k.lower()
            if low == "transfer-encoding":
                te = v.lower()
            elif low == "content-length":
                cl = v
        body = b""
        if "chunked" in te:
            body = _read_chunked(reader)
        elif cl:
            try:
                length = int(cl.split(",")[0].strip())
            except ValueError:
                raise ValueError(f"Content-Length 无效：{cl!r}")
            body = reader.read_exact(length) if length > 0 else b""

        conn_hdr = ""
        for k, v in headers:
            if k.lower() == "connection":
                conn_hdr = v.lower()
        if "close" in conn_hdr:
            keep_alive = False
        elif "keep-alive" in conn_hdr:
            keep_alive = True
        else:
            keep_alive = version.upper() != "HTTP/1.0"

        return Request(method, path, version, headers, body, peer, keep_alive,
                       received_at=t_received)

    # -------------------------------------------------- 转发
    def _host_header(self) -> str:
        default_port = 443 if self.protocol == "https" else 80
        if self.remote_port == default_port:
            return self.remote_host
        return f"{self.remote_host}:{self.remote_port}"

    def _build_forward_bytes(self, req: Request) -> bytes:
        lines = [f"{req.method} {req.path} HTTP/1.1\r\n"]
        for name, value in req.headers:
            low = name.lower()
            # Host 改写为真正的目标地址：设备填的是转发电脑的 IP，原样透传服务器会看不懂
            if low in HOP_BY_HOP or low in ("content-length", "host"):
                continue
            lines.append(f"{name}: {value}\r\n")
        lines.append(f"Host: {self._host_header()}\r\n")
        if req.body:
            lines.append(f"Content-Length: {len(req.body)}\r\n")
        lines.append("Connection: close\r\n\r\n")
        return "".join(lines).encode("latin-1", "replace") + req.body

    def _forward(self, req: Request) -> Response:
        t0 = time.perf_counter()
        sock = socket.create_connection((self.remote_host, self.remote_port), timeout=CONNECT_TIMEOUT)
        try:
            sock.settimeout(RESPONSE_TIMEOUT)
            if self.protocol == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.remote_host)
                sock.settimeout(RESPONSE_TIMEOUT)
            sock.sendall(self._build_forward_bytes(req))
            resp = self._read_response(sock, req.method)
            resp.total_wait = time.perf_counter() - t0
            return resp
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _read_response(self, sock: socket.socket, method: str) -> Response:
        reader = _Reader(sock)
        t_head = None
        while True:
            raw = reader.read_line()
            if not raw:
                raise ConnectionError("服务器没有返回任何响应")
            status_line = raw.decode("latin-1").rstrip("\r\n")
            parts = status_line.split(None, 2)
            if len(parts) < 2 or not parts[0].upper().startswith("HTTP/"):
                raise ValueError(f"无法解析响应状态行：{status_line!r}")
            try:
                code = int(parts[1])
            except ValueError:
                raise ValueError(f"无法解析响应状态码：{status_line!r}")
            reason = parts[2] if len(parts) > 2 else ""

            headers: List[Tuple[str, str]] = []
            while True:
                h = reader.read_line()
                if not h:
                    break
                if h in (b"\r\n", b"\n"):
                    break
                text = h.decode("latin-1").rstrip("\r\n")
                if text[:1] in (" ", "\t") and headers:
                    name, value = headers[-1]
                    headers[-1] = (name, value + " " + text.strip())
                    continue
                name, sep, value = text.partition(":")
                if not sep:
                    continue
                headers.append((name.strip(), value.strip()))

            if t_head is None:
                t_head = time.perf_counter()

            if 100 <= code < 200 and code != 101:
                # 100-continue 等临时响应，跳过继续读真正的响应
                continue
            break

        te = ""
        cl = ""
        for k, v in headers:
            low = k.lower()
            if low == "transfer-encoding":
                te = v.lower()
            elif low == "content-length":
                cl = v

        raw_len = 0
        if code == 101:
            body = b""
        elif method == "HEAD" or code in (204, 304) or 100 <= code < 200:
            body = b""
        elif "chunked" in te:
            body = _read_chunked(reader)
        elif cl:
            try:
                length = int(cl.split(",")[0].strip())
            except ValueError:
                length = 0
            body = reader.read_exact(length) if length > 0 else b""
        else:
            body = reader.read_all()
        raw_len = len(body)

        return Response(status_line, code, reason, headers, body, raw_len,
                        head_wait=0.0, total_wait=0.0)

    # -------------------------------------------------- 回写设备
    def _send_response(self, conn: socket.socket, req: Request, resp: Response) -> None:
        lines = [f"HTTP/1.1 {resp.code} {resp.reason}\r\n" if resp.reason else f"HTTP/1.1 {resp.code}\r\n"]
        for name, value in resp.headers:
            low = name.lower()
            if low in ("connection", "transfer-encoding", "content-length", "keep-alive"):
                continue
            lines.append(f"{name}: {value}\r\n")
        no_body = req.method == "HEAD" or resp.code in (204, 304) or 100 <= resp.code < 200
        if not no_body:
            lines.append(f"Content-Length: {len(resp.body)}\r\n")
        lines.append(f"Connection: {'keep-alive' if req.keep_alive else 'close'}\r\n\r\n")
        conn.sendall("".join(lines).encode("latin-1", "replace") + (b"" if no_body else resp.body))

    def _send_error(self, conn: socket.socket, req: Request, code: int, message: str) -> None:
        body = message.encode("utf-8")
        head = (
            f"HTTP/1.1 {code} Error\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin-1")
        try:
            conn.sendall(head + body)
        except OSError:
            pass

    # -------------------------------------------------- 日志输出
    def _log_request(self, req: Request, total: int) -> None:
        """按原始报文样式输出：首行带来源与方向，头部原样逐行，空一行后正文顶格贴出。"""
        ip = req.peer.rsplit(":", 1)[0]
        self._emit(L_REQ, f"收到：{ip} >{req.method} {req.path} {req.version}")
        for name, value in req.headers:
            self._emit(L_HEAD, f"{name}: {value}", with_time=False)
        self._emit(L_BODY, "", with_time=False)
        if req.body:
            self._log_payload(req.body, req.header("Content-Type"),
                              req.header("Content-Encoding"))
            self._emit(L_BODY, "", with_time=False)

    def _log_response(self, resp: Response) -> None:
        # 服务器返回 4xx/5xx：首行用红色，一眼能看出是服务器那侧报错
        level = L_ERR if resp.code >= 400 else L_RESP
        self._emit(level, f"返回：{resp.status_line}")
        for name, value in resp.headers:
            self._emit(L_HEAD, f"{name}: {value}", with_time=False)
        self._emit(L_BODY, "", with_time=False)
        if resp.body:
            self._log_payload(resp.body, resp.header("Content-Type"),
                              resp.header("Content-Encoding"))
            self._emit(L_BODY, "", with_time=False)

    def _log_payload(self, data: bytes, ctype: str, content_encoding: str) -> None:
        size = len(data)
        payload = _decompress(data, content_encoding) if content_encoding else data
        notes = []
        if size != len(payload):
            notes.append(f"已解压 {content_encoding}：{size} 字节 → 明文 {len(payload)} 字节")

        if _is_binary(payload):
            self._emit(L_BIN, f"二进制数据 {size} 字节（{_describe(payload, ctype)}）")
        else:
            decoded = _decode_text(payload, _charset_of(ctype))
            if decoded is None:
                self._emit(L_BIN, f"二进制数据 {size} 字节（{_describe(payload, ctype)}）")
            else:
                text, enc = decoded
                truncated = False
                if len(text) > MAX_TEXT_CHARS:
                    text = text[:MAX_TEXT_CHARS]
                    truncated = True
                rows = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
                for row in rows:
                    self._emit(L_BODY, row, with_time=False)
                if truncated:
                    notes.append(f"正文超过 {MAX_TEXT_CHARS} 字符已截断，实际 {size} 字节")

        if notes:
            self._emit(L_BODY, "", with_time=False)
            self._emit(L_WARN, "（" + "；".join(notes) + "）", with_time=False)
