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
import requests
from flask import current_app

from eduid_api.common import EduIDAPIError

_TESTING = False


class BaseRequest(object):
    """
    Base request object. Handles decryption and verification of JOSE objects.

    :param request: Request to parse (can be dict for testing)
    :param remote_ip: IP address of client
    :param name: The name of the method invoked

    :type request: str or dict
    :type remote_ip: str | unicode
    :type name: str | unicode
    """

    def __init__(self, request, remote_ip, name):

        self._logger = current_app.logger
        self._signing_key = None

        if isinstance(request, dict) and _TESTING:
            # really only accept a dict when testing, to avoid accidental
            # acceptance of unsigned requests
            parsed = request
        else:
            try:
                decrypted = self._decrypt(request)
                if not decrypted:
                    self._logger.warning("Could not decrypt request from {!r}".format(remote_ip))
                    raise EduIDAPIError("Failed decrypting request")
                verified = self._verify(decrypted, remote_ip)
                if not verified:
                    self._logger.warning("Could not verify decrypted request from {!r}".format(remote_ip))
                    raise EduIDAPIError("Failed verifying signature")
                parsed = verified.claims
            except Exception:
                self._logger.error("Failed decrypting/verifying request:\n{!r}\n-----\n".format(request), exc_info=True)
                raise EduIDAPIError("Failed parsing request")

        assert(isinstance(parsed, dict))

        for req_field in ['version']:
            if req_field not in parsed:
                raise EduIDAPIError("No {!r} in request".format(req_field))

        if parsed['version'] is not 1:
            # really handle missing version below
            raise EduIDAPIError("Unknown request version: {!r}".format(parsed['version']))

        if not name in self.signing_key.allowed_commands:
            raise EduIDAPIError("Method {!r} not allowed with this key".format(name))

        self._parsed_req = parsed
        #cherrypy.request.eduid_api_parsed_req = parsed

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
        decr_key = current_app.mystate.keys.private_key
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
            raise EduIDAPIError('Could not decrypt request')

        if 'v1' not in decrypted.claims:
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
        keys = current_app.mystate.keys.lookup_by_ip(remote_ip)

        if not len(keys):
            self._logger.info("No API keys found for IP address {!r}, can't verify signature".format(remote_ip))
            return False

        # Now, check for a valid signature
        for key in keys:
            if not key.keytype == 'jose':
                self._logger.debug("Ignoring key {!r}".format(key))
                continue
            try:
                jwt = jose.verify(decrypted, key.jwk, alg = current_app.config['JOSE_ALG'])
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

        self._logger.warning("Failed verifying signature on request from {!r} using keys {!r}".format(
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

    @property
    def nonce(self):
        """
        Nonce supplied by client in request.

        :rtype: str
        """
        return self._parsed_req['nonce']


class MakeRequest(object):
    """
    Create a request for sending somewhere.

    :param claims: data to sign, encrypt and send

    :type claims: dict

    :type _api_key: eduid_api.keystore.APIKey | None
    :type _claims: dict
    :type signed_claims: dict
    """
    def __init__(self, claims, alg = 'RS256'):
        self._logger = current_app.logger
        self._request_result = None
        self._api_key = None
        self._claims = claims
        jws = jose.sign(claims, current_app.mystate.keys.private_key.jwk, alg=alg)
        self.signed_claims = {'v1': jose.serialize_compact(jws)}

    def send_request(self, url, name, apikey):
        """
        Encrypt the claims and POST it to url.

        :param url: The URL to POST the data to
        :param name: The HTTP parameter name to put the data in
        :param apikey: API Key to encrypt data with before posting
        :return:

        :type url: str | unicode
        :type apikey: eduid_api.keystore.APIKey
        """
        self._logger.debug("Encrypting signed request using {!r}".format(apikey))
        if not apikey.keytype == 'jose':
            raise EduIDAPIError("Non-jose API key unusuable with send_request")
        self._api_key = apikey
        jwe = jose.encrypt(self.signed_claims, apikey.jwk)
        data = {name: jose.serialize_compact(jwe)}
        self._logger.debug("Sending signed and encrypted request to {!r}".format(url))
        self._request_result = requests.post(url, data = data)
        self._logger.debug("Result of request: {!r}".format(self._request_result))
        return self._request_result

    def decrypt_response(self, ciphertext=None, return_jwt=False):
        """
        Decrypt the response returned from send_request.

        :param ciphertext: Ciphertext to decrypt. If not supplied the last request response is used.
        :param return_jwt: Return the whole JOSE JWT or just the claims

        :type ciphertext: None | str | unicode
        :type return_jwt: bool
        :return: Decrypted result
        :rtype: dict | jose.JWT
        """
        if ciphertext is None:
            ciphertext = self._request_result.text
        jwe = jose.deserialize_compact(ciphertext.replace("\n", ''))
        priv_key = current_app.mystate.keys.private_key
        if not priv_key.keytype == 'jose':
            raise EduIDAPIError("Non-jose private key unusuable with decrypt_response")
        decrypted = jose.decrypt(jwe, priv_key.jwk)
        if not 'v1' in decrypted.claims:
            self._logger.error("No 'v1' in decrypted claims: {!r}\n\n".format(decrypted))
            raise EduIDAPIError("No 'v1' in decrypted claims")

        to_verify = jose.deserialize_compact(decrypted.claims['v1'])
        jwt = jose.verify(to_verify, self._api_key.jwk, alg = current_app.config['JOSE_ALG'])
        self._logger.debug("Good signature on response to request using key: {!r}".format(
            self._api_key.jwk
        ))
        if 'nonce' in self._claims:
            # there was a nonce in the request, verify it is also present in the response
            if not 'nonce' in jwt.claims:
                self._logger.warning("Nonce was present in request, but not in response:\n{!r}".format(
                    jwt.claims
                ))
                raise EduIDAPIError("Request-Response nonce validation error")
            if jwt.claims['nonce'] != self._claims['nonce']:
                self._logger.warning("Response nonce {!r} does not match expected {!r}".format(
                    jwt.claims['nonce'], self._claims['nonce']
                ))
        if return_jwt:
            return jwt
        return jwt.claims
