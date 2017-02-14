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

import vccs_client

import eduid_api.authuser
import eduid_api.authstore
import eduid_api.authfactor
from eduid_api.request import BaseRequest
from eduid_api.common import EduIDAPIError


class MFAAuthRequest(BaseRequest):
    """
    Base request to authenticate with MFA (Multi Factor Authentication).

    Example request POSTed to /mfa_auth:

        {
            "version":    1,
            "nonce":      "3607c28b22abc12ae8b4",
            "token_type": "OATH",

            "OATH": {
                "user_id": "54de24ca8a5da50011e23b41",
                "user_code": "123456"
            }
        }

    The 'nonce' has nothing to do with the token - it allows the API client to
    ensure that a response is in fact related to a specific request.

    :param request: JSON formatted request
    :param logger: logging object
    :param config: config object
    :type request: str
    :type logger: logging.logger
    :type config: eduid_api.config.EduIDAPIConfig

    :type token: AuthOATHTokenRequest | U2FTokenRequest
    """
    def __init__(self, request, remote_ip, logger, config):
        BaseRequest.__init__(self, request, remote_ip, 'mfa_auth', logger, config)

        for req_field in ['nonce', 'version']:
            if req_field not in self._parsed_req:
                raise EduIDAPIError("No {!r} in request".format(req_field))

        if int(self._parsed_req['version']) != 1:
            raise EduIDAPIError("Unknown version in request".format(req_field))

        if self.token_type == 'OATH':
            if 'OATH' not in self._parsed_req:
                raise EduIDAPIError("No 'OATH' in request")
            self.token = AuthOATHTokenRequest(self._parsed_req['OATH'])
        elif self.token_type == 'U2F':
            raise NotImplemented("U2F authentication not implemented yet")
        else:
            raise EduIDAPIError("Unknown token type")

    @property
    def token_type(self):
        """
        Token type is either 'OATH' or 'U2F'.

        :rtype: str
        """
        return self._parsed_req['token_type']


class AuthOATHTokenRequest(object):
    """
    Parse the 'OATH' part of an MFA auth request.

    Example parsed_req:

        {
            "user_id": "54de24ca8a5da50011e23b41",
            "user_code": "123456"
        }
    """
    def __init__(self, parsed_req):
        self._parsed_req = parsed_req
        for req_field in ['user_id', 'user_code']:
            if req_field not in self._parsed_req:
                raise EduIDAPIError("No {!r} in 'OATH' part of request".format(req_field))

    @property
    def user_id(self):
        """
        Unique ID of user in the private eduid API AuthStore.

        :rtype: str | unicode
        """
        return self._parsed_req.get('user_id')

    @property
    def user_code(self):
        """
        The OATH code supplied by the user.

        :rtype: str | unicode
        """
        return str(self._parsed_req['user_code'])


class AuthTokenAction(object):
    """
    Add a token to the authentication backend.

    :param request: Request object
    :param authstore: Credential store
    :param logger: logging object
    :param config: config object

    :type request: MFAAuthRequest
    :type authstore: eduid_api.authstore.APIAuthStore
    :type logger: logging.logger
    :type config: eduid_api.config.EduIDAPIConfig

    :type _user: eduid_api.authuser.APIAuthUser
    :type _authstore: eduid_api.authstore.APIAuthStore
    """
    def __init__(self, request, authstore, logger, config):
        self._request = request
        self._authstore = authstore
        self._logger = logger
        self._config = config
        self._user = self._authstore.get_authuser(request.token.user_id)
        if not self._user:
            raise EduIDAPIError('Unknown user')
        if self._user.owner != self._request.signing_key.owner:
            self._logger.info("Denied authentiation request for user {!r} (owner {!r}) "
                              "made with signing key {!r}/{!r}".format(self._user, self._user.owner,
                                                                       self._request.signing_key,
                                                                       self._request.signing_key.owner))
            raise EduIDAPIError('Wrong administrative domain')
        self._status = None

    def authenticate(self):
        """
        Ask VCCS credential backend to authenticate a credential.
        :rtype: bool
        """
        self._status = False
        self._logger.debug("Authenticating token of type {!r}".format(self._request.token_type))
        client = vccs_client.VCCSClient(base_url=self._config.vccs_base_url)
        user_code = self._request.token.user_code
        if self._request.token_type == 'OATH':
            assert isinstance(self._user.factors, eduid_api.authfactor.EduIDAuthFactorList)
            oath_factors = []
            for factor in self._user.factors.to_list():
                assert isinstance(factor, eduid_api.authfactor.EduIDAuthFactor)   # for pycharm type inference
                if factor.type in ['oath-hotp', 'oath-totp']:
                    this = vccs_client.VCCSOathFactor(factor.type, credential_id=factor.id, user_code=user_code)
                    oath_factors.append(this)
            self._logger.debug("Calling VCCS client at {!r} to authenticate factor(s) {!r}".format(
                self._config.vccs_base_url, oath_factors))
            if client.authenticate(self._user.user_id, oath_factors):
                self._status = True
                return True
        else:
            raise NotImplemented()
        return False

    def response(self):
        """
        Create a response dict to be returned (JSON formatted) to the API client.

        If this is an OK response for an OATH token, this involves creating a
        QR code image with the plaintext key etc. to facilitate provisioning of
        smart phone apps such as Google Authenticator.

        :return: Response
        :rtype: dict
        """
        res = {'status': 'ERROR'}
        if self._status:
            res['status'] = 'OK'
        self._logger.debug("Creating {!r} response for {!r}".format(self._status, self._request))
        if isinstance(self._request.token, AuthOATHTokenRequest):
            if self._status:
                res['OATH'] = {'authenticated': True,
                               }
        res['nonce'] = self._request.nonce  # Copy nonce (request id) from request to response
        return res


def authenticate(req, authstore, logger, config):
    """
    Add a new token to the API auth system.

    :param req: The parsed add-request
    :param authstore: AuthUsers database
    :param logger: Logger
    :param config: Configuration

    :type req: MFAAuthRequest
    :type authstore: eduid_api.authstore.APIAuthStore
    :type logger: logging.logger
    :type config: eduid_api.config.EduIDAPIConfig
    :return: Resppnse dict
    :rtype: dict
    """
    action = AuthTokenAction(req, authstore, logger, config)
    action.authenticate()
    return action.response()
