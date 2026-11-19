"""Unit Tests - test pattern matcher rule file loading."""
import threading
import time
from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)
from pathlib import Path

import libsast
from libsast.core_matcher import helpers

import pytest


RULES_YAML = (
    Path(__file__).parents[1]
    / 'assets' / 'rules' / 'pattern_matcher' / 'patterns.yaml'
).read_bytes()


class RuleRequestHandler(BaseHTTPRequestHandler):
    """Fixed HTTP service for rule download tests."""

    def log_message(self, *args):
        pass

    def _send_rule(self):
        body = RULES_YAML
        self.send_response(200)
        self.send_header('Content-Type', 'text/yaml')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location):
        self.send_response(302)
        self.send_header('Location', location)
        self.end_headers()

    def do_GET(self):
        if self.path == '/patterns.yaml':
            self._send_rule()
        elif self.path == '/redirect/same-origin':
            self._redirect('/patterns.yaml')
        elif self.path == '/redirect/cross-origin':
            port = self.server.server_address[1]
            self._redirect(f'http://localhost:{port}/patterns.yaml')
        elif self.path == '/redirect/file':
            self._redirect('file:///etc/passwd')
        elif self.path == '/redirect/loop':
            self._redirect('/redirect/loop')
        elif self.path == '/huge-declared':
            self.send_response(200)
            self.send_header('Content-Type', 'text/yaml')
            self.send_header(
                'Content-Length', str(helpers.MAX_RULE_SIZE + 1))
            self.end_headers()
            self.wfile.write(b'x' * (helpers.MAX_RULE_SIZE + 1))
        elif self.path == '/huge-stream':
            self.send_response(200)
            self.send_header('Content-Type', 'text/yaml')
            self.end_headers()
            chunk = b'x' * 65536
            sent = 0
            while sent <= helpers.MAX_RULE_SIZE:
                try:
                    self.wfile.write(chunk)
                    self.wfile.flush()
                except OSError:
                    break
                sent += len(chunk)
        elif self.path == '/slow':
            time.sleep(5)
            self._send_rule()
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture(scope='module')
def rule_server():
    server = ThreadingHTTPServer(('127.0.0.1', 0), RuleRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f'http://127.0.0.1:{server.server_address[1]}'
    server.shutdown()
    thread.join()


def test_load_dir():
    base_dir = Path(__file__).parents[1]
    files_dir = base_dir / 'assets' / 'files'
    rules_dir = base_dir / 'assets' / 'rules' / 'pattern_matcher'
    options = {'match_rules': rules_dir.as_posix()}
    paths = [files_dir.as_posix()]
    res = libsast.Scanner(options, paths).scan()
    assert res['pattern_matcher']['test_regex_or']


def test_load_multiple_rules():
    base_dir = Path(__file__).parents[1]
    files_dir = base_dir / 'assets' / 'files'
    rules_dir = base_dir / 'assets' / 'multiple'
    options = {'match_rules': rules_dir.as_posix()}
    paths = [files_dir.as_posix()]
    res = libsast.Scanner(options, paths).scan()['pattern_matcher']
    assert res['test_regex_or']
    assert res['test_regex']
    assert res['test_regex_and']
    assert res['test_regex_or']
    assert res['test_regex_and_not']
    assert res['test_regex_or']


def test_load_file():
    base_dir = Path(__file__).parents[1]
    files_dir = base_dir / 'assets' / 'files'
    rule_file = base_dir / 'assets' / 'rules'
    rule_file = rule_file / 'pattern_matcher' / 'patterns.yaml'
    options = {'match_rules': rule_file.as_posix()}
    paths = [files_dir.as_posix()]
    res = libsast.Scanner(options, paths).scan()
    assert res['pattern_matcher']['test_regex_or']


def test_load_url(rule_server):
    rule_url = f'{rule_server}/patterns.yaml'
    base_dir = Path(__file__).parents[1]
    files_dir = base_dir / 'assets' / 'files'
    options = {'match_rules': rule_url}
    paths = [files_dir.as_posix()]
    res = libsast.Scanner(options, paths).scan()
    assert res['pattern_matcher']['test_regex_or']


def test_load_url_same_origin_redirect(rule_server):
    rule_url = f'{rule_server}/redirect/same-origin'
    base_dir = Path(__file__).parents[1]
    files_dir = base_dir / 'assets' / 'files'
    options = {'match_rules': rule_url}
    paths = [files_dir.as_posix()]
    res = libsast.Scanner(options, paths).scan()
    assert res['pattern_matcher']['test_regex_or']


def test_load_url_cross_origin_redirect_blocked(rule_server):
    rule_url = f'{rule_server}/redirect/cross-origin'
    base_dir = Path(__file__).parents[1]
    files_dir = base_dir / 'assets' / 'files'
    options = {'match_rules': rule_url}
    paths = [files_dir.as_posix()]
    with pytest.raises(libsast.exceptions.RuleDownloadError):
        libsast.Scanner(options, paths).scan()


def test_load_url_file_scheme_redirect_blocked(rule_server):
    rule_url = f'{rule_server}/redirect/file'
    base_dir = Path(__file__).parents[1]
    files_dir = base_dir / 'assets' / 'files'
    options = {'match_rules': rule_url}
    paths = [files_dir.as_posix()]
    with pytest.raises(libsast.exceptions.RuleDownloadError):
        libsast.Scanner(options, paths).scan()


def test_load_url_https_downgrade_blocked():
    with pytest.raises(libsast.exceptions.RuleDownloadError):
        helpers._validate_redirect(
            'https://example.com/rules.yaml',
            'http://example.com/rules.yaml')


def test_load_url_too_many_redirects(rule_server):
    rule_url = f'{rule_server}/redirect/loop'
    with pytest.raises(libsast.exceptions.RuleDownloadError):
        helpers.download_rule(rule_url)


def test_load_url_oversized_declared(rule_server):
    rule_url = f'{rule_server}/huge-declared'
    with pytest.raises(libsast.exceptions.RuleDownloadError):
        helpers.download_rule(rule_url)


def test_load_url_oversized_stream(rule_server):
    rule_url = f'{rule_server}/huge-stream'
    with pytest.raises(libsast.exceptions.RuleDownloadError):
        helpers.download_rule(rule_url)


def test_load_url_timeout(rule_server):
    rule_url = f'{rule_server}/slow'
    with pytest.raises(libsast.exceptions.RuleDownloadError):
        helpers.download_rule(rule_url, timeout=1)


def test_load_invalid_url(rule_server):
    rule_url = f'{rule_server}/does-not-exist.yaml'
    base_dir = Path(__file__).parents[1]
    files_dir = base_dir / 'assets' / 'files'
    options = {'match_rules': rule_url}
    paths = [files_dir.as_posix()]
    with pytest.raises(libsast.exceptions.RuleDownloadError):
        libsast.Scanner(options, paths).scan()


def test_load_file_invalid_path():
    base_dir = Path(__file__).parents[1]
    files_dir = base_dir / 'assets' / 'files'
    rule_file = base_dir / 'assets' / 'rules' / 'patterns.yoo'
    options = {'match_rules': rule_file.as_posix()}
    paths = [files_dir.as_posix()]
    with pytest.raises(libsast.exceptions.InvalidRuleError):
        libsast.Scanner(options, paths).scan()


def test_load_file_invalid_yaml():
    base_dir = Path(__file__).parents[1]
    files_dir = base_dir / 'assets' / 'files'
    rule_file = base_dir / 'assets' / 'invalid' / 'invalid_yaml.yaml'
    options = {'match_rules': rule_file.as_posix()}
    paths = [files_dir.as_posix()]
    with pytest.raises(libsast.exceptions.YamlRuleParseError):
        libsast.Scanner(options, paths).scan()


def test_load_file_invalid_type():
    base_dir = Path(__file__).parents[1]
    files_dir = base_dir / 'assets' / 'files'
    rule_file = base_dir / 'assets' / 'invalid' / 'invalid_type.yaml'
    options = {'match_rules': rule_file.as_posix()}
    paths = [files_dir.as_posix()]
    with pytest.raises(libsast.exceptions.MatcherNotFoundError):
        libsast.Scanner(options, paths).scan()


def test_load_file_missing_type():
    base_dir = Path(__file__).parents[1]
    files_dir = base_dir / 'assets' / 'files'
    rule_file = base_dir / 'assets' / 'invalid' / 'missing_type.yaml'
    options = {'match_rules': rule_file.as_posix()}
    paths = [files_dir.as_posix()]
    with pytest.raises(libsast.exceptions.PatternKeyMissingError):
        libsast.Scanner(options, paths).scan()


def test_load_file_missing_pattern():
    base_dir = Path(__file__).parents[1]
    files_dir = base_dir / 'assets' / 'files'
    rule_file = base_dir / 'assets' / 'invalid' / 'missing_pattern.yaml'
    options = {'match_rules': rule_file.as_posix()}
    paths = [files_dir.as_posix()]
    with pytest.raises(libsast.exceptions.PatternKeyMissingError):
        libsast.Scanner(options, paths).scan()


def test_ignore_comments():
    base_dir = Path(__file__).parents[1]
    files_dir = base_dir / 'assets' / 'files' / 'comments.java'
    rule_file = base_dir / 'assets' / 'rules'
    rule_file = rule_file / 'pattern_matcher' / 'patterns.yaml'
    options = {'match_rules': rule_file.as_posix()}
    paths = [files_dir.as_posix()]
    res = libsast.Scanner(options, paths).scan()
    assert res['pattern_matcher'] == {}
