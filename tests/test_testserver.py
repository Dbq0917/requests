import hashlib
import re
import socket
import threading
import time

import pytest

import requests
from tests.testserver.server import Server, consume_socket_content


class TestTestServer:
    def test_basic(self):
        """messages are sent and received properly"""
        question = b"success?"
        answer = b"yeah, success"

        def handler(sock):
            text = sock.recv(1000)
            assert text == question
            sock.sendall(answer)

        with Server(handler) as (host, port):
            sock = socket.socket()
            sock.connect((host, port))
            sock.sendall(question)
            text = sock.recv(1000)
            assert text == answer
            sock.close()

    def test_server_closes(self):
        """the server closes when leaving the context manager"""
        with Server.basic_response_server() as (host, port):
            sock = socket.socket()
            sock.connect((host, port))

            sock.close()

        with pytest.raises(socket.error):
            new_sock = socket.socket()
            new_sock.connect((host, port))

    def test_text_response(self):
        """the text_response_server sends the given text"""
        server = Server.text_response_server(
            "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nroflol"
        )

        with server as (host, port):
            r = requests.get(f"http://{host}:{port}")

            assert r.status_code == 200
            assert r.text == "roflol"
            assert r.headers["Content-Length"] == "6"

    def test_basic_response(self):
        """the basic response server returns an empty http response"""
        with Server.basic_response_server() as (host, port):
            r = requests.get(f"http://{host}:{port}")
            assert r.status_code == 200
            assert r.text == ""
            assert r.headers["Content-Length"] == "0"

    def test_basic_waiting_server(self):
        """the server waits for the block_server event to be set before closing"""
        block_server = threading.Event()

        with Server.basic_response_server(wait_to_close_event=block_server) as (
            host,
            port,
        ):
            sock = socket.socket()
            sock.connect((host, port))
            sock.sendall(b"send something")
            time.sleep(2.5)
            sock.sendall(b"still alive")
            block_server.set()  # release server block

    def test_multiple_requests(self):
        """multiple requests can be served"""
        requests_to_handle = 5

        server = Server.basic_response_server(requests_to_handle=requests_to_handle)

        with server as (host, port):
            server_url = f"http://{host}:{port}"
            for _ in range(requests_to_handle):
                r = requests.get(server_url)
                assert r.status_code == 200

            # the (n+1)th request fails
            with pytest.raises(requests.exceptions.ConnectionError):
                r = requests.get(server_url)

    @pytest.mark.skip(reason="this fails non-deterministically under pytest-xdist")
    def test_request_recovery(self):
        """can check the requests content"""
        # TODO: figure out why this sometimes fails when using pytest-xdist.
        server = Server.basic_response_server(requests_to_handle=2)
        first_request = b"put your hands up in the air"
        second_request = b"put your hand down in the floor"

        with server as address:
            sock1 = socket.socket()
            sock2 = socket.socket()

            sock1.connect(address)
            sock1.sendall(first_request)
            sock1.close()

            sock2.connect(address)
            sock2.sendall(second_request)
            sock2.close()

        assert server.handler_results[0] == first_request
        assert server.handler_results[1] == second_request

    def test_requests_after_timeout_are_not_received(self):
        """the basic response handler times out when receiving requests"""
        server = Server.basic_response_server(request_timeout=1)

        with server as address:
            sock = socket.socket()
            sock.connect(address)
            time.sleep(1.5)
            sock.sendall(b"hehehe, not received")
            sock.close()

        assert server.handler_results[0] == b""

    def test_request_recovery_with_bigger_timeout(self):
        """a biggest timeout can be specified"""
        server = Server.basic_response_server(request_timeout=3)
        data = b"bananadine"

        with server as address:
            sock = socket.socket()
            sock.connect(address)
            time.sleep(1.5)
            sock.sendall(data)
            sock.close()

        assert server.handler_results[0] == data

    def test_server_finishes_on_error(self):
        """the server thread exits even if an exception exits the context manager"""
        server = Server.basic_response_server()
        with pytest.raises(Exception):
            with server:
                raise Exception()

        assert len(server.handler_results) == 0

        # if the server thread fails to finish, the test suite will hang
        # and get killed by the jenkins timeout.

    def test_server_finishes_when_no_connections(self):
        """the server thread exits even if there are no connections"""
        server = Server.basic_response_server()
        with server:
            pass

        assert len(server.handler_results) == 0

        # if the server thread fails to finish, the test suite will hang
        # and get killed by the jenkins timeout.


class TestDigestAuthQopList:
    """Digest auth against servers that format qop as a list."""

    REALM = "testrealm"
    NONCE = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
    USERNAME = "user"
    PASSWORD = "pass"

    def _is_valid_digest(self, request_text):
        match = re.search(
            r"^Authorization: Digest (.*)$", request_text, re.IGNORECASE | re.MULTILINE
        )
        if not match:
            return False

        values = {
            name.lower(): quoted or unquoted
            for name, quoted, unquoted in re.findall(
                r'(\w+)=(?:"([^"]*)"|([^,\s]+))', match.group(1)
            )
        }
        required = {
            "username",
            "realm",
            "nonce",
            "uri",
            "response",
            "qop",
            "nc",
            "cnonce",
        }
        if not required.issubset(values) or values["qop"] != "auth":
            return False

        method, uri, _ = request_text.splitlines()[0].split(" ", 2)
        if uri != values["uri"]:
            return False

        def md5(value):
            return hashlib.md5(value.encode("utf-8"), usedforsecurity=False).hexdigest()

        ha1 = md5(f"{self.USERNAME}:{self.REALM}:{self.PASSWORD}")
        ha2 = md5(f"{method}:{uri}")
        expected = md5(
            f"{ha1}:{self.NONCE}:{values['nc']}:{values['cnonce']}:auth:{ha2}"
        )
        return expected == values["response"]

    def _digest_server(self, qop_directive, requests_to_handle=2):
        def handler(sock):
            request_text = consume_socket_content(sock).decode("latin-1")
            if self._is_valid_digest(request_text):
                response = (
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            else:
                response = (
                    "HTTP/1.1 401 Unauthorized\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n"
                    f'WWW-Authenticate: Digest realm="{self.REALM}", '
                    f'nonce="{self.NONCE}", {qop_directive}, algorithm=MD5\r\n'
                    "\r\n"
                )
            sock.sendall(response.encode("latin-1"))
            return request_text

        return Server(handler, requests_to_handle=requests_to_handle)

    @pytest.mark.parametrize(
        "qop_directive",
        (
            'qop="auth"',
            'qop="auth,auth-int"',
            'qop="auth, auth-int"',
            'qop="AUTH, AUTH-INT"',
            'qop="UNKNOWN, auth"',
            "qop=auth, auth-int",
            "qop=auth-int, auth",
        ),
    )
    def test_digest_auth_qop_list(self, qop_directive):
        server = self._digest_server(qop_directive)
        with server as (host, port):
            response = requests.get(
                f"http://{host}:{port}/",
                auth=requests.auth.HTTPDigestAuth(self.USERNAME, self.PASSWORD),
            )
            assert response.status_code == 200
            assert 'qop="auth"' in response.request.headers["Authorization"]

        assert len(server.handler_results) == 2

    @pytest.mark.parametrize(
        "qop_directive",
        (
            'qop="auth-int"',
            'qop="UNKNOWN, OTHER"',
            "qop=auth-int, UNKNOWN",
        ),
    )
    def test_unsupported_qop_names_field(self, qop_directive):
        server = self._digest_server(qop_directive, requests_to_handle=1)
        with server as (host, port):
            with pytest.raises(ValueError, match="qop"):
                requests.get(
                    f"http://{host}:{port}/",
                    auth=requests.auth.HTTPDigestAuth(self.USERNAME, self.PASSWORD),
                )
