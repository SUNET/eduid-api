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

from eduid_api.request import BaseRequest
from eduid_api.common import EduIDAPIError


class AEADGenRequest(BaseRequest):
    """
    A request to generate an AEAD.

    The AEAD will be returned, optionally together with it's plaintext (!).
    This is used to create OATH token credentials.

    Example AEAD generation request POSTed to /aead_gen:

        {
            "version":    1,
            "nonce":      "74b4a9a07084799548e5",
            "length":     20,
            "plaintext":  True
        }

    The 'nonce' has nothing to do with the AEADs nonce - it allows the API client to
    ensure that a response is in fact related to a specific request.

    :param request: JSON formatted request
    :param logger: logging object
    :param config: config object
    :type request: str
    :type logger: eduid_api.log.EduIDAPILogger
    :type config: eduid_api.config.EduIDAPIConfig
    """
    def __init__(self, request, remote_ip, logger, config):
        BaseRequest.__init__(self, request, remote_ip, 'aead_gen', logger, config)

        for req_field in ['length', 'version']:
            if req_field not in self._parsed_req:
                raise EduIDAPIError("No {!r} in request".format(req_field))

        if int(self._parsed_req['version']) != 1:
            raise EduIDAPIError("Unknown version in request".format(req_field))

    @property
    def length(self):
        """
        AEAD length requested (in bytes).

        :rtype: int
        """
        return int(self._parsed_req['length'])

    @property
    def plaintext(self):
        """
        Client requests plaintext in response.

        :rtype: bool
        """
        return bool(self._parsed_req.get('plaintext', False))


class OATHAEAD(object):
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
        self.secret = xored.encode('hex')
        aead = config.yhsm.generate_aead_simple(chr(0x0), self.keyhandle, self.secret)
        self.aead = aead.data.encode('hex')
        self.nonce = aead.nonce.encode('hex')


class AEADGenAction(object):
    """
    Generate a new AEAD using a YubiHSM.

    :param request: Request object
    :param logger: logging object
    :param config: config object

    :type request: AEADGenRequest
    :type logger: eduid_api.log.EduIDAPILogger
    :type config: eduid_api.config.EduIDAPIConfig
    """
    def __init__(self, request, logger, config):
        self._request = request
        self._logger = logger
        self._config = config
        self._status = False

        self.aead = OATHAEAD(logger, config, num_bytes = self._request.length)
        self._status = True

    def response(self):
        """
        Create a response dict to be returned (JSON formatted) to the API client.

        :return: Response
        :rtype: dict
        """
        res = {'status': 'ERROR'}
        if self._status:
            res['status'] = 'OK'
            res['aead'] = {'data': self.aead.aead,
                           'nonce': self.aead.nonce,
                           'key_handle': self.aead.keyhandle,
                           }
            if self._request.plaintext:
                res['aead']['secret'] = self.aead.secret
        self._logger.debug("Creating {!r} response for {!r}".format(self._status, self._request))
        res['nonce'] = self._request.nonce  # Copy nonce (request id) from request to response
        return res
