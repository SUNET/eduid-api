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
eduID API request checking and parsing
"""

import jose
from eduid_api.common import EduIDAPIError

_TESTING = False


class BaseRequest():
    """
    Base request object. Handles decryption and verification of JOSE objects.

    :param request: Request to parse (can be dict for testing)
    :param remote_ip: IP address of client
    :param name: The name of the function invoked
    :param logger: logging object
    :param config: config object

    :type request: str or dict
    :type remote_ip: basestring
    :type name: basestring
    :type logger: eduid_api.log.EduIDAPILogger
    :type config: eduid_api.config.EduIDAPIConfig
    """

    def __init__(self, request, remote_ip, name, logger, config):

        self._logger = logger
        self._config = config
        self._signing_key = None

        if isinstance(request, dict) and _TESTING:
            # really only accept a dict when testing, to avoid accidental
            # acceptance of unsigned requests
            parsed = request
        else:
            try:
                decrypted = self._decrypt(request)
                verified = self._verify(decrypted, remote_ip)
                if not verified:
                    return
                parsed = verified.claims
            except Exception:
                logger.error("Failed decrypting/verifying request:\n{!r}\n-----\n".format(request), traceback=True)
                raise EduIDAPIError("Failed parsing request")

        assert(isinstance(parsed, dict))

        if parsed.get('version', 1) is not 1:
            # really handle missing version below
            raise EduIDAPIError("Unknown request version: {!r}".format(parsed['version']))

        for req_field in ['version']:
            if req_field not in parsed:
                raise EduIDAPIError("No {!r} in request".format(req_field))

        self._parsed_req = parsed

    def __repr__(self):
        return ('<{} @{:#x}>'.format(
            self.__class__.__name__,
            id(self),
        ))

    def _decrypt(self, request):
        """
        Decrypt a JOSE encrypted request.

        :param request: Request to parse

        :type request: str

        :rtype: bool or jose.JWS
        """
        jwe = jose.deserialize_compact(request.replace("\n", ''))

        decrypted = None
        decr_key = self._config.keys.private_key
        if not decr_key:
            self._logger.error("No asymmetric private key (named '_private') found in the keystore")
            return False

        self._logger.debug("Trying to decrypt request with key {!r}".format(decr_key))
        try:
            decrypted = jose.decrypt(jwe, decr_key.jwk, expiry_seconds = decr_key.expiry_seconds)
            self._logger.debug("Decrypted {!r}".format(decrypted))
        except jose.Expired as ex:
            self._logger.warning("Request encrypted with key {!r} has expired: {!r}".format(decr_key, ex))
        except jose.Error as ex:
            self._logger.warning("Failed decrypt with key {!r}: {!r}".format(decr_key, ex))
            pass

        if not 'v1' in decrypted.claims:
            self._logger.error("No 'v1' in decrypted claims: {!r}".format(decrypted))
            return False
        to_verify = jose.deserialize_compact(decrypted.claims['v1'])
        #logger.debug("Decrypted claims to verify: {!r}".format(to_verify))
        return to_verify

    def _verify(self, decrypted, remote_ip):
        """
        verify a JOSE signed objecct.

        :param decrypted: Data to verify
        :param remote_ip: IP address of client

        :type decrypted: jose.JWS
        :type remote_ip: basestring
        :rtype: jose.JWT or False
        """
        keys = self._config.keys.lookup_by_ip(remote_ip)

        if not len(keys):
            self._logger.info("No API keys found for IP address {!r}".format(remote_ip))
            return False

        # Now, check for a valid signature
        for key in keys:
            if not key.keytype == 'jose':
                self._logger.debug("Ignoring key {!r}".format(key))
                continue
            try:
                jwt = jose.verify(decrypted, key.jwk)
                self._logger.debug("Good signature on request from {!r} using key {!r}: {!r}".format(
                    remote_ip, key, jwt
                ))
                self._signing_key = key
                return jwt
            except ValueError:
                self._logger.debug("Ignoring key unusable with this algorithm: {!r}".format(key))
                pass
            except jose.Error as ex:
                self._logger.debug("Tried verifying signature using key {!r}: {!r}".format(key, ex))
                pass

        self._logger.warning("Failed verifying signature on requset from {!r} using keys {!r}".format(
            remote_ip, keys
        ))
        return False

    @property
    def signing_key(self):
        """
        :return: APIKey used to sign this request
        :rtype: eduid_api.keystore.APIKey | None
        """
        return self._signing_key
