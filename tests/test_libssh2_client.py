import unittest
import os
import logging

from embedded_server.embedded_server import start_server, make_socket, \
     logger as server_logger
from pssh.libssh2_client import SSHClient, logger as pssh_logger


PKEY_FILENAME = os.path.sep.join([os.path.dirname(__file__), 'test_client_private_key'])
# USER_KEY = paramiko.RSAKey.from_private_key_file(PKEY_FILENAME)

server_logger.setLevel(logging.DEBUG)
pssh_logger.setLevel(logging.DEBUG)
logging.basicConfig()


class LibSSH2ClientTest(unittest.TestCase):

    def setUp(self):
        self.fake_cmd = 'echo me'
        self.fake_resp = 'me'
        self.user_key = PKEY_FILENAME
        self.host = '127.0.0.1'
        self.listen_socket = make_socket(self.host)
        self.listen_port = self.listen_socket.getsockname()[1]
        self.server = start_server(self.listen_socket)
        self.client = SSHClient(self.host, port=self.listen_port)

    def tearDown(self):
        del self.server
        del self.listen_socket

    def test_execute(self):
        channel, host, stdout, stderr = self.client.exec_command(
            self.fake_cmd)
        output = list(stdout)
        stderr = list(stderr)
        expected = [self.fake_resp]
        self.assertEqual(expected, output)
