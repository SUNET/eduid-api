#
# Copyright (c) 2015 NORDUnet A/S
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
Crypto keystore for eduID API backend.

Every system sending requets to the eduID API need to have a JOSE
public key in our keystore.

Example keystore:

    {"test1": {"JWK": {"file": "/opt/eduid/etc/test-client.pem"},
               "ip_addresses": ["192.0.2.111"]
              },

     "_private": {"JWK": {"file": "/opt/eduid/etc/api-snakeoil.key"},
                  "ip_addresses": []
                 }
    }

The eduID API service's private key need to be provided in the special "_private" entry.
"""

import simplejson

from eduid_api.common import EduIDAPIError


class KeyStore(object):

    """
    The keystore contains API client authentication and authorization information.
    """

    def __init__(self, keystore_fn):
        if not keystore_fn:
            self._keys = []
            return

        try:
            f = open(keystore_fn, 'r')
            data = f.read()
            f.close()
            data = simplejson.loads(data)
            assert (type(data) == dict)
        except Exception as ex:
            raise EduIDAPIError("Failed loading config file {!r}: {!r}".format(keystore_fn, ex))

        self._keys = [APIKey(name, value) for (name, value) in data.items()]

    def lookup_by_ip(self, ip):
        """
        Return all APIKeys matching the IP address supplied.

        :param ip: IP address (of client presumably)
        :type ip: basestring

        :rtype: [APIKey()]
        """
        res = [this for this in self._keys if ip in this.ip_addresses or '*' in this.ip_addresses]
        return res

    def lookup_by_url(self, url):
        """
        Return all APIKeys matching the URL supplied. For outgoing requests.

        :param url: URL (of server presumably)
        :type url: str | unicode

        :rtype: [APIKey()]
        """
        res = [this for this in self._keys if url in this.urls]
        return res

    @property
    def private_key(self):
        """
        Get the private key for the API service (key named '_private').

        :rtype: APIKey() or None
        """
        res = None
        for key in self._keys:
            if key.name == '_private':
                res = key
                break
        return res


class APIKey(object):
    """
    API key entrys contain sign/encrypt credentials and authorization information.
    """
    def __init__(self, name, data):
        self._name = name
        self._data = data
        self._key = None

    def __repr__(self):
        return '<{cl} instance at {addr}: {name!r}, type={keytype!r}>'.format(
            cl = self.__class__.__name__,
            addr = hex(id(self)),
            name = self._name,
            keytype = self.keytype,
        )

    @property
    def name(self):
        """
        Get the name of this API key.

        :return: Name
        :rtype: [basestring]
        """
        return self._name

    @property
    def owner(self):
        """
        Get the name of the owner of this API key.

        The owners name is associated with e.g. any authusers created using this key.
        The reason for having a separate owner name and key name is to allow an organization
        to have more than one API key (key rollover, multiple API clients etc.).

        If no 'owner' is given in the key metadata, the keys name is used as default value.

        :return: Owners name
        :rtype: [basestring]
        """
        return self._data.get('owner', self._name)

    @property
    def ip_addresses(self):
        """
        Get the list of IP addresses registered with this API key.

        IP addresses are given for clients connecting to this API service.

        :return: List of IP addresses
        :rtype: [basestring]
        """
        return self._data.get('ip_addresses', [])

    @property
    def urls(self):
        """
        Get the list of URLs registered with this API key.

        URLs are provided for keys used when this API service needs to connect to other services.

        :return: List of URLs
        :rtype: [basestring]
        """
        return self._data.get('urls', [])

    @property
    def keytype(self):
        """
        Get the type of API key. Typically 'jose'.

        :return: API key type
        :rtype: basestring
        """
        return self._data.get('keytype', 'jose')

    @property
    def expiry_seconds(self):
        """
        :return: Expire time in seconds
        :rtype: int or None
        """
        return self._data.get('expiry_seconds')

    @property
    def jwk(self):
        """
        :return: JWK dict
        :rtype: dict
        """
        if not self._key:
            if 'file' in self._data.get('JWK'):
                # If configuration looks like this:
                #  {"dash-fre-1": {"JWK": {"file": "/path/to/client-dash-fre-1.pem"},
                #    ...
                # then load the private key from the path supplied.
                _keyfile = self._data.get('JWK')['file']
                try:
                    fd = open(_keyfile)
                    self._key = dict(k = fd.read())
                except Exception as ex:
                    raise EduIDAPIError("Failed loading key file {!r}: {!r}".format(_keyfile, ex))
            else:
                self._key = self._data.get('JWK')
            if not 'k' in self._key:
                EduIDAPIError("Bad JWK for key {!r}: {!r}".format(self, self._key))
        return self._key

    @property
    def allowed_commands(self):
        """
        Get the allowed commands for this client.

        :return: List of allowed command names
        :rtype: [str | unicode]
        """
        return self._data.get('allowed_commands', [])
