import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from subdomain_recon.http_utils import HTTPSourceError, require_ok_response
from subdomain_recon.sources.base import SourceContext
from subdomain_recon.sources.crtsh import CrtShSource


class _FakeResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text

    def json(self):
        if self._json_data is None:
            raise ValueError("no JSON body")
        return self._json_data


def test_require_ok_response_passes_through_2xx():
    r = _FakeResponse(200, json_data=[])
    assert require_ok_response(r, "crt.sh", "http://x") is r


def test_require_ok_response_raises_on_none():
    try:
        require_ok_response(None, "crt.sh", "http://x")
        assert False, "expected HTTPSourceError"
    except HTTPSourceError as e:
        assert "no response" in str(e)
        assert "crt.sh" in str(e)


def test_require_ok_response_raises_on_non_2xx_with_body_snippet():
    r = _FakeResponse(502, text="Bad Gateway from crt.sh")
    try:
        require_ok_response(r, "crt.sh", "http://x")
        assert False, "expected HTTPSourceError"
    except HTTPSourceError as e:
        assert "HTTP 502" in str(e)
        assert "Bad Gateway" in str(e)


def test_crtsh_source_raises_on_connection_failure_not_silent_empty():
    """Regression test: crt.sh returning 0 hosts used to be indistinguishable
    from crt.sh being completely unreachable (the exact symptom reported --
    'crt.sh: 0 normalized hosts' while the user's network was clearly having
    issues reaching crt.sh). Now a real connection failure raises, so it
    shows up as a Provider Health 'error' with the actual reason."""
    ctx = SourceContext(config={"retries": 0, "http_timeout": 1}, cache=None, api_keys={})
    with mock.patch("subdomain_recon.sources.crtsh.request_with_retry", return_value=None):
        try:
            CrtShSource().fetch("example.com", ctx)
            assert False, "expected HTTPSourceError"
        except HTTPSourceError as e:
            assert "crt.sh" in str(e)
            assert "no response" in str(e)


def test_crtsh_source_returns_hosts_on_success():
    ctx = SourceContext(config={"retries": 0, "http_timeout": 1}, cache=None, api_keys={})
    fake_resp = _FakeResponse(200, json_data=[{"name_value": "a.example.com\nb.example.com"}])
    with mock.patch("subdomain_recon.sources.crtsh.request_with_retry", return_value=fake_resp):
        hosts = CrtShSource().fetch("example.com", ctx)
    assert hosts == ["a.example.com", "b.example.com"]


def test_crtsh_source_empty_json_array_is_a_valid_zero_result():
    """A clean 200 response with zero certificates is a real 'found
    nothing', not an error -- must NOT raise."""
    ctx = SourceContext(config={"retries": 0, "http_timeout": 1}, cache=None, api_keys={})
    fake_resp = _FakeResponse(200, json_data=[])
    with mock.patch("subdomain_recon.sources.crtsh.request_with_retry", return_value=fake_resp):
        hosts = CrtShSource().fetch("example.com", ctx)
    assert hosts == []
