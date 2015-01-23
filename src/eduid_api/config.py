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
                    'mongodb_uri': '127.0.0.1',
                    'add_raw_allow': '',       # comma-separated list of IP addresses
                    'listen_addr': '0.0.0.0',
                    'listen_port': '8511',
                    'ssl_adapter': 'builtin',  # one of cherrypy.wsgiserver.ssl_adapters
                    'server_cert': None,       # SSL cert filename
                    'server_key': None,        # SSL key filename
                    'cert_chain': None,        # SSL certificate chain filename, or None
                    'broker_url': 'amqp://',   # AMQP broker URL. See Celery documentation for details.
                    'keystore_fn': '',
                    }

_CONFIG_SECTION = 'eduid_api'


class EduIDAPIConfig():
    """
    Application configuration.

    Loads an INI file and provides configuration data.

    :param filename: Path to INI file.
    :param debug: Debug setting, from command line parsing.
    :type filename: basestring
    :type debug: bool
    """

    def __init__(self, filename, debug):
        self.section = _CONFIG_SECTION
        _CONFIG_DEFAULTS['debug'] = str(debug)
        self.config = ConfigParser.ConfigParser(_CONFIG_DEFAULTS)
        if not self.config.read([filename]):
            raise EduIDAPIError("Failed loading config file {!r}".format(filename))
        # split on comma and strip. cache result.
        tmp_add_raw_allow = str(self.config.get(self.section, 'add_raw_allow')) # for pylint
        self._parsed_add_raw_allow = \
            [x.strip() for x in tmp_add_raw_allow.split(',')]
        self.keys = eduid_api.keystore.KeyStore(self.keystore_fn)

    @property
    def logdir(self):
        """
        Path to CherryPy logfiles. Something like '/var/log/eduid' maybe.

        :rtype: basestring or None
        """
        res = self.config.get(self.section, 'logdir')
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
