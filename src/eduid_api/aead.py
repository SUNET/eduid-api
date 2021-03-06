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

import os

import eduid_api.request
from eduid_api.common import EduIDAPIError


class OATHAEAD(object):
    """
    Contact AEAD generation service and generate a new AEAD
    for an OATH credential, or generate one locally if a YubiHSM is available.

    Since OATH credentials would be useless unless we can communicate the HMAC key to
    the user, we can't just ask the VCCS backend to generate the credential and just
    give us a reference. Instead, we have to ask an OATH AEAD generating service to
    generate the OATH AEAD that will later on be usable for authenticating the user,
    but also give us the actual HMAC key.

    :param logger: logging object
    :param config: config object

    :type logger: eduid_api.log.EduIDAPILogger
    :type config: eduid_api.config.EduIDAPIConfig
    """
    def __init__(self, logger, config):
        self._logger = logger
        self._config = config

        if config.yhsm:
            _aead = YHSM_OATHAEAD(logger, config)
            self._data = _aead.to_dict(plaintext=True)
            return

        # No local YubiHSM - access one remotely from another instance of this
        # API and it's function aead_gen.

        claims = {'version': 1,
                  'nonce': os.urandom(8).encode('hex'),  # Not AEAD nonce, just 'verify response' nonce
                  'length': 20,                          # OATH is HMAC-SHA1 == 160 bits == 20 bytes
                  'plaintext': True,                     # Need the plaintext to share with the user
                  }
        url = self._config.oath_aead_gen_url
        req = eduid_api.request.MakeRequest(claims, self._logger, self._config)
        api_key = self._config.keys.lookup_by_url(url)
        if not api_key:
            self._logger.error("No API Key found for URL {!r}".format(url))
            raise EduIDAPIError("No API Key found for OATH AEAD service")
        req.send_request(url, 'request', api_key[0])
        data = req.decrypt_response()
        self._logger.debug("Got response: {!r}".format(data))
        if data['status'] != 'OK':
            self._logger.error("OATH AEAD generation failed: {!r}".format(data.get('reason')))
            raise EduIDAPIError("OATH AEAD generation failed")
        self._data = data['aead']

    @property
    def secret(self):
        """
        The plaintext HMAC key. Called 'secret' to get filtered in Sentry reports.
        :rtype: str | unicode
        """
        return self._data['secret']

    @property
    def key_handle(self):
        """
        The YubiHSM key handle that was used to generate the AEAD.
        :rtype: int
        """
        return self._data['key_handle']

    @property
    def aead(self):
        """
        The AEAD.
        :rtype: str | unicode
        """
        return self._data['data']

    @property
    def nonce(self):
        """
        The AEAD nonce.
        :rtype: str | unicode
        """
        return self._data['nonce']


class YHSM_OATHAEAD(object):
    """
    Contact AEAD generation service and generate a new AEAD for an OATH credential.

    :param logger: logging object
    :param config: config object

    :type logger: eduid_api.log.EduIDAPILogger
    :type config: eduid_api.config.EduIDAPIConfig
    """
    def __init__(self, logger, config, num_bytes = 20):
        self.keyhandle = config.oath_aead_keyhandle
        self._logger = logger
        if not self.keyhandle:
            raise EduIDAPIError('No OATH AEAD keyhandle configured')

        self._logger.debug("Generating {!r} bytes AEAD using key_handle 0x{:x}".format(num_bytes, self.keyhandle))

        from_os = os.urandom(num_bytes).encode('hex')
        from_hsm = config.yhsm.random(num_bytes)
        # XOR together num_bytes from the YubiHSM's RNG with nu_bytes from /dev/urandom.
        xored = ''.join([chr(ord(a) ^ ord(b)) for (a, b) in zip(from_hsm, from_os)])
        self.secret = xored
        # Make the key inside the AEAD only usable with the YubiHSM YSM_HMAC_SHA1_GENERATE function
        # Enabled flags 00010000 = YSM_HMAC_SHA1_GENERATE
        flags = '\x00\x00\x01\x00'  # struct.pack("< I", 0x10000)
        aead = config.yhsm.generate_aead_simple(chr(0x0), self.keyhandle, self.secret + flags)
        self.aead = aead.data.encode('hex')
        self.nonce = aead.nonce.encode('hex')

    def to_dict(self, plaintext=False):
        """
        Serialize generated AEAD into a dict.

        :param plaintext: Add the plaintext secret into the result.

        :return: Generated AEAD as dict
        :rtype: dict
        """
        res = {'data': self.aead,
               'nonce': self.nonce,
               'key_handle': self.keyhandle,
               }
        if plaintext:
            res['secret'] = self.secret.encode('hex')
        return res
