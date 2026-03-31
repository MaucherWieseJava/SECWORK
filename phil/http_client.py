import os
import sys
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def _detect_windows_proxy() -> str:
    """Try to read the proxy from Windows registry."""
    if sys.platform != "win32":
        return ""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        )
        enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
        if enabled:
            proxy, _ = winreg.QueryValueEx(key, "ProxyServer")
            winreg.CloseKey(key)
            if proxy and not proxy.startswith("http"):
                proxy = f"http://{proxy}"
            print(f"[http] Windows proxy detected: {proxy}")
            return proxy
        winreg.CloseKey(key)
    except Exception:
        pass
    return ""


def get_session() -> requests.Session:
    """Create a requests session with retry logic and proxy support."""
    session = requests.Session()

    # Retry: 3 attempts, exponential backoff (2s, 4s, 8s), retry on common errors
    retry = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    # Proxy priority:
    # 1. Explicit env var (HTTPS_PROXY / HTTP_PROXY)
    # 2. Windows registry (automatic detection)
    http_proxy = os.environ.get("HTTPS_PROXY",
                os.environ.get("https_proxy",
                os.environ.get("HTTP_PROXY",
                os.environ.get("http_proxy", ""))))

    if not http_proxy:
        http_proxy = _detect_windows_proxy()

    if http_proxy:
        session.proxies = {
            "http": http_proxy,
            "https": http_proxy,
        }

    # Skip SSL verification for corporate proxies that do MITM/SSL inspection
    # Set ADITI_NO_SSL_VERIFY=1 if you get SSL errors behind a proxy
    if os.environ.get("ADITI_NO_SSL_VERIFY", "").strip() == "1":
        session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    return session
