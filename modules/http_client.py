"""
requests-compatible HTTP client backed by curl_cffi.

Stock ``requests``/``httpx`` hand the TLS handshake to Python's ``ssl`` module
(OpenSSL), which produces a JA3/JA4 fingerprint that matches no real browser.
Most WAFs and anti-bot layers check that fingerprint before headers, cookies
or timing, so a script can have a perfect User-Agent and still get rejected
on the handshake alone. curl_cffi drives its own TLS stack to reproduce a
real browser's cipher suites, extensions and ALPN, so the handshake matches
what it claims to be in the User-Agent.

Every module should import this instead of ``requests`` directly:

    from . import http_client as requests

The public surface (get/post/Session/exceptions/RequestException/HTTPError)
mirrors ``requests`` closely enough that no other call-site changes are
needed.
"""
from curl_cffi import requests as _requests
from curl_cffi.requests import exceptions

try:
    from .config import tls_impersonate as _IMPERSONATE
except ImportError:
    _IMPERSONATE = "chrome131"

RequestException = exceptions.RequestException
HTTPError = exceptions.HTTPError
Timeout = exceptions.Timeout
ConnectionError = exceptions.ConnectionError
Session = _requests.Session


def _impersonated(kwargs):
    kwargs.setdefault("impersonate", _IMPERSONATE)
    return kwargs


def get(url, **kwargs):
    return _requests.get(url, **_impersonated(kwargs))


def post(url, **kwargs):
    return _requests.post(url, **_impersonated(kwargs))


def head(url, **kwargs):
    return _requests.head(url, **_impersonated(kwargs))
