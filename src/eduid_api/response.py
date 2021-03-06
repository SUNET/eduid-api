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

import jose
import cherrypy

from eduid_api.common import EduIDAPIError


class BaseResponse(object):
    """
    :param data: Data to put in response
    :param logger: logging object
    :param config: config object

    :type data: dict
    :type logger: eduid_api.log.EduIDAPILogger
    :type config: eduid_api.config.EduIDAPIConfig
    """
    def __init__(self, data, logger, config):
        self._logger = logger
        self._config = config
        self._data = data
        assert self._data, dict
        return

    def to_string(self, remote_key = None, remote_ip = None):
        """
        Sign and encrypt this response.

        :param remote_key: Encrypt response to this key
        :param remote_ip: If no remote_key, look up a key for this remote_ip

        :type remote_key: str or None
        :type remote_ip: str or None

        :rtype: str
        """
        sign_key = self._config.keys.private_key
        self._logger.debug("Signing response using key {!r}".format(sign_key))
        jws = jose.sign(self._data, sign_key.jwk, alg = self._config.jose_alg)
        signed_claims = {'v1': jose.serialize_compact(jws)}
        self._logger.debug("Signed response: {!r}".format(signed_claims))
        encrypt_key = remote_key
        if not encrypt_key:
            # default to the first key found using the remote_ip in case no key was supplied
            ip_keys = self._config.keys.lookup_by_ip(remote_ip)
            if not ip_keys:
                self._logger.warning("Found no key for IP {!r}, can't encrypt response:\n{!r}".format(
                    remote_ip, self._data
                ))
                raise EduIDAPIError("No API Key found - can't encrypt response")
            encrypt_key = ip_keys[0]
        self._logger.debug("Encrypting claims to key {!r}".format(encrypt_key))
        jwe = jose.encrypt(signed_claims, encrypt_key.jwk)
        return jose.serialize_compact(jwe)


class ErrorResponse(BaseResponse):
    """
    Error response class.
    """

    def __init__(self, message, logger, config):
        error = {'version': 1,
                 'status': 'FAIL',
                 'reason': message,
                 }
        try:
            if 'nonce' in cherrypy.request.eduid_api_parsed_req:
                error['nonce'] = cherrypy.request.eduid_api_parsed_req['nonce']
        except AttributeError:
            pass
        BaseResponse.__init__(self, error, logger, config)
