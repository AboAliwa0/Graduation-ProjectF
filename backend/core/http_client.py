"""
==========================================================
CyberScan Enterprise
HTTP Client
----------------------------------------------------------
Author  : Graduation Project Team
Purpose : Unified HTTP client used by all scanner plugins.
Version : 1.0
==========================================================
"""

import time
from typing import Optional, Dict, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from backend.core.constants import (
    DEFAULT_HEADERS,
    DEFAULT_TIMEOUT,
    RETRY_COUNT,
    RETRY_DELAY,
    VERIFY_SSL,
    ALLOW_REDIRECTS
)

from backend.core.exceptions import (
    ConnectionException,
    TimeoutException,
    SSLException,
    RedirectException,
    InvalidURLException,
    HTTPException
)


class HTTPClient:
    """
    Unified HTTP Client.

    Every scanner must use this class instead of requests.
    """

    def __init__(self):

        self.session = requests.Session()

        retry = Retry(
            total=RETRY_COUNT,
            backoff_factor=RETRY_DELAY,
            status_forcelist=[
                429,
                500,
                502,
                503,
                504
            ],
            allowed_methods=[
                "GET",
                "POST",
                "HEAD",
                "OPTIONS"
            ]
        )

        adapter = HTTPAdapter(max_retries=retry)

        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.session.headers.update(DEFAULT_HEADERS)

    def _request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> requests.Response:

        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        kwargs.setdefault("verify", VERIFY_SSL)
        kwargs.setdefault("allow_redirects", ALLOW_REDIRECTS)

        start = time.perf_counter()

        try:

            response = self.session.request(
                method,
                url,
                **kwargs
            )

            elapsed = time.perf_counter() - start

            response.elapsed_time = round(elapsed, 4)

            return response

        except requests.exceptions.ConnectTimeout:
            raise TimeoutException()

        except requests.exceptions.ReadTimeout:
            raise TimeoutException()

        except requests.exceptions.SSLError:
            raise SSLException()

        except requests.exceptions.TooManyRedirects:
            raise RedirectException()

        except requests.exceptions.InvalidURL:
            raise InvalidURLException()

        except requests.exceptions.ConnectionError:
            raise ConnectionException()

        except requests.exceptions.RequestException as ex:
            raise HTTPException(str(ex))

    def get(self, url: str, **kwargs):
        return self._request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self._request("POST", url, **kwargs)

    def head(self, url: str, **kwargs):
        return self._request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs):
        return self._request("OPTIONS", url, **kwargs)