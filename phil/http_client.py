import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def get_session() -> requests.Session:
    """Create a requests session with retry logic and proxy support."""
    session = requests.Session()

    # Retry: 3 attempts, exponential backoff (1s, 2s, 4s), retry on common errors
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    # Proxy support via environment variables
    # Set HTTPS_PROXY or HTTP_PROXY on your work machine, e.g.:
    #   set HTTPS_PROXY=http://proxy.company.com:8080
    #   set HTTP_PROXY=http://proxy.company.com:8080
    http_proxy = os.environ.get("HTTP_PROXY", os.environ.get("http_proxy", ""))
    https_proxy = os.environ.get("HTTPS_PROXY", os.environ.get("https_proxy", ""))
    if http_proxy or https_proxy:
        session.proxies = {
            "http": http_proxy,
            "https": https_proxy,
        }

    # Optional: skip SSL verification for corporate proxies that do MITM
    # Set ADITI_NO_SSL_VERIFY=1 if you get SSL errors behind a proxy
    if os.environ.get("ADITI_NO_SSL_VERIFY", "").strip() == "1":
        session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    return session
