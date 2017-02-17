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
    """
    def __init__(self):
        self._data = {}

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


class OATHAEAD_YHSM(OATHAEAD):
    """
    Generate an AEAD using a local YubiHSM.

    :param logger: logging object
    :param config: config object

    :type logger: eduid_api.log.EduIDAPILogger
    :type config: eduid_api.config.EduIDAPIConfig
    """
    def __init__(self, logger, state, num_bytes = 20):
        super(OATHAEAD, self).__init__(self)
        self.keyhandle = state.oath_aead_keyhandle
        self._logger = logger
        if not self.keyhandle:
            raise EduIDAPIError('No OATH AEAD keyhandle configured')

        self._logger.debug("Generating {!r} bytes AEAD using key_handle 0x{:x}".format(num_bytes, self.keyhandle))

        from_os = os.urandom(num_bytes).encode('hex')
        from_hsm = state.yhsm.random(num_bytes)
        # XOR together num_bytes from the YubiHSM's RNG with nu_bytes from /dev/urandom.
        xored = ''.join([chr(ord(a) ^ ord(b)) for (a, b) in zip(from_hsm, from_os)])
        # Make the key inside the AEAD only usable with the YubiHSM YSM_HMAC_SHA1_GENERATE function
        # Enabled flags 00010000 = YSM_HMAC_SHA1_GENERATE
        flags = '\x00\x00\x01\x00'  # struct.pack("< I", 0x10000)
        aead = state.yhsm.generate_aead_simple(chr(0x0), self.keyhandle, self.secret + flags)

        self._data = {'data': aead.data.encode('hex'),
                      'nonce': aead.nonce.encode('hex'),
                      'key_handle': self.keyhandle,
                      'secret': xored,
                      }


class OATHAEAD_Remote(OATHAEAD):
    """
    Generate an AEAD using a remote AEAD generation service.

    :param logger: logging object
    :param config: config object

    :type logger: eduid_api.log.EduIDAPILogger
    :type config: eduid_api.config.EduIDAPIConfig
    """
    def __init__(self, logger, url, keys):
        super(OATHAEAD, self).__init__()

        # No local YubiHSM - access one remotely from another instance of this
        # API and it's function aead_gen.

        claims = {'version': 1,
                  'nonce': os.urandom(8).encode('hex'),  # Not AEAD nonce, just 'verify response' nonce
                  'length': 20,                          # OATH is HMAC-SHA1 == 160 bits == 20 bytes
                  'plaintext': True,                     # Need the plaintext to share with the user
                  }
        req = eduid_api.request.MakeRequest(claims)
        api_key = keys.lookup_by_url(url)
        if not api_key:
            logger.error("No API Key found for URL {!r}".format(url))
            raise EduIDAPIError("No API Key found for OATH AEAD service")
        req.send_request(url, 'request', api_key[0])
        data = req.decrypt_response()
        logger.debug("Got response: {!r}".format(data))
        if data['status'] != 'OK':
            logger.error("OATH AEAD generation failed: {!r}".format(data.get('reason')))
            raise EduIDAPIError("OATH AEAD generation failed")
        self._data = data['aead']
