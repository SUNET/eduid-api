#!/usr/bin/python
#
# Copyright (c) 2013, 2015 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#
"""
Configuration (file) handling for eduID API backend.
"""

import eduid_api.keystore
import ConfigParser
from eduid_api.common import EduIDAPIError


_CONFIG_DEFAULTS = {'debug': False,            # overwritten in EduIDAPIConfig.__init__()
                    'logdir': None,
                    'logfile': None,
                    'syslog': '1',                    # '1' for True, '0' for False
                    'syslog_socket': '/dev/log',
                    'syslog_debug': '0',              # '1' for True, '0' for False
                    'mongodb_uri': '',
                    'add_raw_allow': '',       # comma-separated list of IP addresses
                    'listen_addr': '0.0.0.0',
                    'listen_port': '8511',
                    'ssl_adapter': 'builtin',  # one of cherrypy.wsgiserver.ssl_adapters
                    'server_cert': None,       # SSL cert filename
                    'server_key': None,        # SSL key filename
                    'cert_chain': None,        # SSL certificate chain filename, or None
                    'broker_url': 'amqp://',   # AMQP broker URL. See Celery documentation for details.
                    'keystore_fn': '',
                    'jose_alg': 'RS256',       # JOSE signing algorithm
                    'vccs_base_url': 'http://localhost:8550/',
                    'oath_aead_keyhandle': None,
                    'oath_yhsm_device': '',
                    'oath_aead_gen_url': '',   # URL to another instance of eduid-api with a YubiHSM
                    }

_CONFIG_SECTION = 'eduid_api'


class EduIDAPIConfig():
    """
    Application configuration.

    Loads an INI file and provides configuration data.

    :param filename: Path to INI file.
    :param debug: Debug setting, from command line parsing.
    :type filename: str | unicode
    :type debug: bool

    :type yhsm: pyhsm.YHSM | None
    :type keys: eduid_api.keystore.KeyStore
    """

    def __init__(self, filename, debug):
        self.section = _CONFIG_SECTION
        _CONFIG_DEFAULTS['debug'] = str(debug)
        self.config = ConfigParser.ConfigParser(_CONFIG_DEFAULTS)
        if not self.config.read([filename]):
            raise EduIDAPIError("Failed loading config file {!r}".format(filename))
        # split on comma and strip. cache result.
        tmp_add_raw_allow = str(self.config.get(self.section, 'add_raw_allow'))  # for pylint
        self._parsed_add_raw_allow = \
            [x.strip() for x in tmp_add_raw_allow.split(',')]
        self.keys = eduid_api.keystore.KeyStore(self.keystore_fn)

        self._parsed_oath_aead_keyhandle = None
        self.yhsm = None
        kh_str = self.config.get(self.section, 'oath_aead_keyhandle')
        if self.oath_yhsm_device or kh_str:
            try:
                import pyhsm
                if kh_str:
                    self._parsed_oath_aead_keyhandle = pyhsm.util.key_handle_to_int(kh_str.strip())
                try:
                    self.yhsm = pyhsm.YHSM(device = self.oath_yhsm_device)
                    # stir up the pool
                    for _ in xrange(10):
                        self.yhsm.random(32)
                except pyhsm.exception.YHSM_Error:
                    raise EduIDAPIError('YubiHSM init error')
            except ImportError:
                raise EduIDAPIError("yhsm settings present, but import of pyhsm failed")

    @property
    def logdir(self):
        """
        Path to CherryPy logfiles. Something like '/var/log/eduid' maybe.

        :rtype: str | unicode | None
        """
        res = self.config.get(self.section, 'logdir')
        if not res:
            res = None
        return res

    @property
    def logfile(self):
        """
        Path to application logfile. Something like '/var/log/idp/eduid_idp.log' maybe.
        """
        res = self.config.get(self.section, 'logfile')
        if not res:
            res = None
        return res

    @property
    def syslog(self):
        """
        Set to True to log to syslog (boolean).

        :rtype: bool
        """
        return self.config.getboolean(self.section, 'syslog')

    @property
    def syslog_socket(self):
        """
        Syslog socket to log to (string). Something like '/dev/log' maybe.
        """
        res = self.config.get(self.section, 'syslog_socket')
        if not res:
            res = None
        return res

    @property
    def mongodb_uri(self):
        """
        MongoDB connection URI. See MongoDB documentation for details.

        :rtype: basestring
        """
        return self.config.get(self.section, 'mongodb_uri')

    @property
    def add_raw_allow(self):
        """
        List of IP addresses from which to accept add_raw commands (string).

        Comma-separated list of IP addresses.

        :rtype: basestring
        """
        return self._parsed_add_raw_allow

    @property
    def debug(self):
        """
        Set to True to log debug messages (boolean).

        :rtype: bool
        """
        return self.config.getboolean(self.section, 'debug')

    @property
    def syslog_debug(self):
        """
        Set to True to log debug messages to syslog (also requires syslog_socket) (boolean).
        """
        return self.config.getboolean(self.section, 'syslog_debug')

    @property
    def listen_addr(self):
        """
        IP address to listen on.

        :rtype: basestring
        """
        return self.config.get(self.section, 'listen_addr')

    @property
    def listen_port(self):
        """
        The port the eduID API backend should listen on (integer).

        :rtype: int
        """
        return self.config.getint(self.section, 'listen_port')

    @property
    def ssl_adapter(self):
        """
        CherryPy SSL adapter class to use (must be one of cherrypy.wsgiserver.ssl_adapters)
        """
        return self.config.get(self.section, 'ssl_adapter')

    @property
    def server_cert(self):
        """
        SSL certificate filename (None == SSL disabled)

        :rtype: basestring or None
        """
        return self.config.get(self.section, 'server_cert')

    @property
    def server_key(self):
        """
        SSL private key filename (None == SSL disabled)

        :rtype: basestring or None
        """
        return self.config.get(self.section, 'server_key')

    @property
    def cert_chain(self):
        """
        SSL certificate chain filename

        :rtype: basestring
        """
        return self.config.get(self.section, 'cert_chain')

    @property
    def broker_url(self):
        """
        Celery broker_url setting. See Celery documentation for details.

        If a broker is configured, the eduID Attribute Manager will be
        notified on database changes.

        :rtype: basestring
        """
        return self.config.get(self.section, 'broker_url')

    @property
    def keystore_fn(self):
        """
        Keystore filename.

        See eduid_api.config.KeyStore() for information about the format of this file.

        :rtype: basestring
        """
        return self.config.get(self.section, 'keystore_fn')

    @property
    def jose_alg(self):
        """
        JOSE signing algorithm.

        :rtype: basestring
        """
        return self.config.get(self.section, 'jose_alg')

    @property
    def vccs_base_url(self):
        """
        VCCS authentication backend service base URL.

        :rtype: basestring
        """
        return self.config.get(self.section, 'vccs_base_url')

    @property
    def oath_aead_gen_url(self):
        """
        OATH AEAD generator service base URL.

        :rtype: str | unicode
        """
        return self.config.get(self.section, 'oath_aead_gen_url')

    @property
    def oath_aead_keyhandle(self):
        """
        The keyhandle to use when creating OATH AEADs with a YubiHSM (integer).

        :rtype: int | None
        """
        return self._parsed_oath_aead_keyhandle

    @property
    def oath_yhsm_device(self):
        """
        OATH YubiHSM device name (default: /dev/ttyACM0).

        :rtype: str | unicode
        """
        return self.config.get(self.section, 'oath_yhsm_device')

