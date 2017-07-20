# This file is part of parallel-ssh.

# Copyright (C) 2014-2017 Panos Kittenis

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation, version 2.1.

# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

"""LibSSH2 based SSH client package"""


import logging
import os
import pwd
from socket import gaierror as sock_gaierror, error as sock_error

from gevent import sleep
from gevent.select import select
from gevent import socket
from pssh_libssh2 import libssh2

from .exceptions import UnknownHostException, AuthenticationException, \
     ConnectionErrorException, SSHException
from .constants import DEFAULT_RETRIES

host_logger = logging.getLogger('pssh.host_logger')
logger = logging.getLogger(__name__)

LIBSSH2_ERROR_EAGAIN = -37

class SSHClient(object):
    """Libssh2 based SSH client"""

    IDENTITIES = [
        os.path.expanduser('~/.ssh/id_rsa'),
        os.path.expanduser('~/.ssh/id_dsa'),
        os.path.expanduser('~/.ssh/identity')
    ]

    def __init__(self, host,
                 user=None, password=None, port=None,
                 pkey=None, forward_ssh_agent=None,
                 num_retries=DEFAULT_RETRIES, agent=None,
                 allow_agent=True, timeout=10,
                 proxy_host=None, proxy_port=22, proxy_user=None, 
                 proxy_password=None, proxy_pkey=None, channel_timeout=None,
                 _openssh_config_file=None):
        self.host = host
        self.user = user if user else pwd.getpwuid(os.getuid()).pw_name
        self.password = password
        self.port = port if port else 22
        self.pkey = pkey
        self.session = libssh2.Session()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.forward_ssh_agent = forward_ssh_agent
        self.num_retries = num_retries
        self.session.setblocking(0)
        self._connect()
        self.startup()
        self.auth()
        self.channel = self.open_channel()

    def _connect(self, retries=1):
        self.sock.setblocking(1)
        try:
            self.sock.connect((self.host, self.port))
        except sock_error as ex:
            logger.error("Error connecting to host '%s:%s' - retry %s/%s",
                         self.host, self.port, retries, self.num_retries)
            while retries < self.num_retries:
                sleep(5)
                return self._connect(retries=retries+1)
            error_type = ex.args[1] if len(ex.args) > 1 else ex.args[0]
            raise ConnectionErrorException(
                "Error connecting to host '%s:%s' - %s - retry %s/%s",
                self.host, self.port, str(error_type), retries,
                self.num_retries,)
        self.sock.setblocking(0)

    def startup(self):
        return self._eagain(self.session.startup, self.sock)

    def _agent_auth(self):
        self.session.setblocking(1)
        self.session.userauth_agent(self.user)
        self.session.setblocking(0)

    def _pkey_auth(self):
        pub_file = "{}.pub".format(self.pkey)
        self._eagain(
            self.session.userauth_publickey_fromfile,
            self.user,
            pub_file,
            self.pkey,
            self.password if self.password is not None else '')

    def _identity_auth(self):
        for identity_file in self.IDENTITIES:
            if not os.path.isfile(identity_file):
                continue
            pub_file = "%s.pub" % (identity_file)
            try:
                self._eagain(
                    self.session.userauth_publickey_fromfile,
                    self.user,
                    pub_file,
                    identity_file,
                    self.password if self.password is not None else '')
            except Exception:
                logger.debug("Authentication with identity file %s failed, "
                             "continuing with other identities",
                             identity_file)
                continue
            else:
                logger.debug("Authentication succeeded with identity file %s",
                             identity_file)
                return
        raise AuthenticationException("No authentication methods succeeded")

    def auth(self):
        if self.pkey is not None:
            return self._pkey_auth()
        try:
            self._agent_auth()
        except Exception as ex:
            logger.debug("Agent auth failed with %s, "
                         "continuing with other authentication methods",
                         ex)
        else:
            logger.debug("Authentication with SSH Agent succeeded")
            return
        self._identity_auth()

    def open_channel(self):
        chan = self.session.open_session()
        while chan is None:
            self._wait_select()
            chan = self.session.open_session()
        return chan

    def __del__(self):
        self._eagain(self.session.close)

    def _run_with_retries(self, func, count=1, *args, **kwargs):
        while func(*args, **kwargs) == LIBSSH2_ERROR_EAGAIN:
            if count > self.num_retries:
                raise AuthenticationException(
                    "Error authenticating %s@%s", self.user, self.host,)
            count += 1

    def _execute(self, cmd, use_pty=True):
        if self.channel.closed:
            logger.debug("Channel closed - opening new channel")
            self.channel = self.open_channel()
        try:
            if use_pty:
                self._eagain(self.channel.pty)
            self._eagain(self.channel.execute, cmd)
        except Exception as ex:
            if '-22' in ex.message:
                logger.debug("Channel closed - opening new channel")
                self.channel = self.open_channel()
                self._eagain(self.channel.execute, cmd)
            else:
                raise
        sleep()

    def join(self):
        raise NotImplementedError

    def read_output(self):
        while not self.channel.eof():
            remainder = ""
            self._wait_select()
            _pos = 0
            _size, _data = self._eagain(self.channel.read_ex)
            while _size > 0:
                while _pos < _size:
                    linesep = _data.find(os.linesep, _pos)
                    if linesep > 0:
                        if len(remainder) > 0:
                            yield remainder + _data[_pos:linesep].strip()
                            remainder = ""
                        else:
                            yield _data[_pos:linesep].strip()
                        _pos = linesep + 1
                    else:
                        remainder += _data[_pos:]
                        break
                _size, _data = self._eagain(self.channel.read_ex)

    def read_stderr(self):
        data = self._eagain(self.channel.read_stderr)
        if data is not None:
            for line in data.splitlines():
                line.strip()
                yield line

    def _eagain(self, func, *args, **kwargs):
        ret = func(*args, **kwargs)
        while ret == LIBSSH2_ERROR_EAGAIN:
            self._wait_select()
            ret = func(*args, **kwargs)
        return ret

    def _wait_select(self):
        """
        Find out from libssh2 if its blocked on read or write and wait
        accordingly.
        Return immediately if libssh2 is not blocked
        """
        blocked = self.session.blockdirections()
        if blocked == 0:
            return
        readfds = [self.sock] if (blocked & 01) else ()
        writefds = [self.sock] if (blocked & 02) else ()
        select(readfds, writefds, [])

    def read_output_buffer(self, output_buffer, prefix='',
                           callback=None,
                           callback_args=None,
                           encoding='utf-8'):
        """Read from output buffers and log to host_logger

        :param output_buffer: Iterator containing buffer
        :type output_buffer: iterator
        :param prefix: String to prefix log output to ``host_logger`` with
        :type prefix: str
        :param callback: Function to call back once buffer is depleted:
        :type callback: function
        :param callback_args: Arguments for call back function
        :type callback_args: tuple
        """
        for line in output_buffer:
            output = line.decode(encoding)
            host_logger.info("[%s]%s\t%s", self.host, prefix, output,)
            yield output
        if callback:
            callback(*callback_args)

    def exec_command(self, command, sudo=False, user=None,
                     use_pty=True, use_shell=True, shell=None):
        self._execute(command, use_pty=use_pty)
        return self.channel, self.host, \
            self.read_output(), \
            iter([]), \
            self.channel
