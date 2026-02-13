from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ScanResult:
    host: str
    port: int
    is_open: bool
    banner: Optional[str] = None
    error: Optional[str] = None


def resolve_target(target: str) -> str:
    """
    Resolve a domain to an IP (or validate IP).
    Why: lets user pass 'example.com' or '192.168.0.10'.
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as e:
        raise ValueError(f"Unable to resolve target: {target}") from e


def scan_port(ip: str, port: int, timeout: float, grab_banner: bool = False) -> ScanResult:
    """
    TCP connect scan:
    - try to connect to ip:port
    - open if connect succeeds
    Banner grabbing is optional and conservative.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((ip, port))
        banner = None

        # Banner grabbing: safe-ish but not always meaningful and can be noisy.
        # We'll keep it optional.
        if grab_banner:
            try:
                sock.sendall(b"\r\n")
                data = sock.recv(128)
                if data:
                    banner = data.decode(errors="ignore").strip()
            except Exception:
                banner = None

        return ScanResult(host=ip, port=port, is_open=True, banner=banner)
    except (socket.timeout, ConnectionRefusedError):
        return ScanResult(host=ip, port=port, is_open=False)
    except OSError as e:
        return ScanResult(host=ip, port=port, is_open=False, error=str(e))
    finally:
        try:
            sock.close()
        except Exception:
            pass
