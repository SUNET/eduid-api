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

import bson
import base64
import vccs_client

import eduid_api.authuser
from eduid_api.request import BaseRequest
from eduid_api.common import EduIDAPIError
from eduid_api.aead import OATHAEAD

import qrcode
import qrcode.image.svg
import StringIO


class MFAAddRequest(BaseRequest):
    """
    Base request to handle adding a MFA (Multi Factor Authentication) token.

    Example OATH request POSTed to /mfa_add:

        {
            "version":    1,
            "nonce":      "74b4a9a07084799548e5",
            "token_type": "OATH",

            "OATH": {
                "type":    "oath-totp",
                "account": "user@example.org",
                "digits":  6,
                "issuer":  "TestIssuer"
            }
        }

    The 'nonce' has nothing to do with the token - it allows the API client to
    ensure that a response is in fact related to a specific request.

    :param request: JSON formatted request
    :param logger: logging object
    :param config: config object
    :type request: str
    :type logger: eduid_api.log.EduIDAPILogger
    :type config: eduid_api.config.EduIDAPIConfig

    :type token: AddOATHTokenRequest | AddU2FTokenRequest
    """
    def __init__(self, request, remote_ip, logger, config):
        BaseRequest.__init__(self, request, remote_ip, 'mfa_add', logger, config)

        for req_field in ['nonce', 'token_type', 'version']:
            if req_field not in self._parsed_req:
                raise EduIDAPIError("No {!r} in request".format(req_field))

        if int(self._parsed_req['version']) != 1:
            raise EduIDAPIError("Unknown version in request".format(req_field))

        if self.token_type == 'OATH':
            if 'OATH' not in self._parsed_req:
                raise EduIDAPIError("No 'OATH' in request")
            self.token = AddOATHTokenRequest(self._parsed_req['OATH'])
        elif self.token_type == 'U2F':
            self.token = AddU2FTokenRequest(self._parsed_req['U2F'])
        else:
            raise EduIDAPIError("Unknown token type")

    @property
    def token_type(self):
        """
        Token type is either 'OATH' or 'U2F'.

        :rtype: str
        """
        return self._parsed_req['token_type']


class AddOATHTokenRequest(object):
    """
    Parse the 'OATH' part of an MFA add request.

    Example parsed_req:

        {
            "type":    "oath-totp",
            "account": "user@example.org",
            "digits":  6,
            "issuer":  "TestIssuer"
        }
    """
    def __init__(self, parsed_req):
        self._parsed_req = parsed_req
        for req_field in ['digits', 'issuer', 'account']:
            if req_field not in self._parsed_req:
                raise EduIDAPIError("No {!r} in 'OATH' part of request".format(req_field))
        if self.type not in ['hotp', 'totp']:
            raise EduIDAPIError("Invalid type in 'OATH' part of request")

    @property
    def type(self):
        """
        OATH type - currently supported are 'hotp' (event based) and 'totp' (time based).

        :rtype: int
        """
        return self._parsed_req.get('type', 'totp')

    @property
    def digits(self):
        """
        Number of digits in OATH codes.

        :rtype: int
        """
        return int(self._parsed_req['digits'])

    @property
    def initial_counter(self):
        """
        Initial counter value for token (optional, defaults to zero).

        :rtype: int
        """
        return int(self._parsed_req.get('initial_counter', 0))

    @property
    def issuer(self):
        """
        Authentication service name. Used in the generated QR code.

        :rtype: str
        """
        return self._parsed_req['issuer']

    @property
    def account(self):
        """
        Account name. Used in the generated QR code.

        :rtype: str
        """
        return self._parsed_req['account']

    def key_uri(self, aead):
        """
        :param aead: Generated OATH AEAD.
        :type aead: OATHAEAD

        Create a provisioning URL for use with e.g. Google Authenticator.

        :rtype: str
        """
        return "otpauth://{oath_type}/{issuer}:{account}?secret={secret}&issuer={issuer}".format(
            oath_type = self.type,
            issuer = self.issuer,
            account = self.account,
            secret = base64.b32encode(aead.secret.decode('hex')),
        )


class AddU2FTokenRequest(object):

    """
    Parse the 'OATH' part of an MFA add request.

    Example parsed_req:

    """
    # XXX add example parsed_req above
    def __init__(self, parsed_req):
        self._parsed_req = parsed_req
        for req_field in ['appId', 'challenge', 'clientData', 'registrationData', 'version']:
            if req_field not in self._parsed_req:
                raise EduIDAPIError("No {!r} in 'U2F' part of request".format(req_field))

    @property
    def appId(self):
        """
        The application id that the RP would like to assert.

        :rtype: [str]
        """
        return self._parsed_req['appId']

    @property
    def challenge(self):
        """
        The websafe-base64-encoded challenge.

        :rtype: str
        """
        return self._parsed_req['challenge']

    @property
    def clientData(self):
        """
        The client data created by the FIDO client, websafe-base64 encoded.

        :rtype: str
        """
        return self._parsed_req['clientData']

    @property
    def registrationData(self):
        """
        The raw registration response websafe-base64.

        :rtype: str
        """
        return self._parsed_req['registrationData']

    @property
    def version(self):
        """
        Version of the protocol that the to-be-registered U2F token must speak. E.g. "U2F_V2".

        :rtype: str
        """
        return self._parsed_req['version']


class AddTokenAction(object):
    """
    Add a token to the authentication backend.

    :param request: Request object
    :param authstore: Credential store
    :param logger: logging object
    :param config: config object

    :type request: MFAAddRequest
    :type authstore: eduid_api.authstore.APIAuthStore
    :type logger: eduid_api.log.EduIDAPILogger
    :type config: eduid_api.config.EduIDAPIConfig

    :type aead: OATHAEAD
    :type _user: eduid_api.authuser.APIAuthUser
    :type _token_id: bson.ObjectId
    :type _authstore: eduid_api.authstore.APIAuthStore
    """
    def __init__(self, request, authstore, logger, config):
        self._request = request
        self._authstore = authstore
        self._logger = logger
        self._config = config
        self.aead = None
        self._token_id = bson.ObjectId()  # unique id for new token
        self._status = None
        self._factor = None
        self._user = None

    def add_to_authbackend(self):
        """
        Ask VCCS credential backend to store a new credential.
        """
        self._logger.debug("Adding token of type {!r} to authbackend".format(self._request.token_type))
        if self._request.token_type == 'OATH':
            self._get_oath_aead()
            # dump all attributes on self to logger
            #for attr in dir(self):
            #    self._logger.debug("ATTR {!r}: {!r}".format(attr, getattr(self, attr)))
            token_type = 'oath-{!s}'.format(self._request.token.type)
            self._factor = vccs_client.VCCSOathFactor(
                token_type,
                str(self._token_id),
                nonce = self.aead.nonce,
                aead = self.aead.aead,
                key_handle = self.aead.key_handle,
                digits = self._request.token.digits,
                oath_counter = self._request.token.initial_counter,
                )
        else:
            raise NotImplemented()
        self._logger.debug("Calling VCCS client at {!r} to add factor {!r}".format(
            self._config.vccs_base_url, self._factor))
        client = vccs_client.VCCSClient(base_url=self._config.vccs_base_url)
        client.add_credentials(str(self._token_id), [self._factor])
        self._status = True

    def add_to_authstore(self):
        """
        Store information about this credential in the authstore (eduid-API private database).
        :return: None
        """
        factors = [{
            'id': self._token_id,
            'type': 'oath-totp',
            'created_by': 'eduid-api',
            }]
        user_dict = {
            'status': 'enabled',
            'owner': self._request.signing_key.owner,
            'factors': factors,
        }
        self._logger.debug("Adding user to authstore: {!r}".format(user_dict))
        self._user = eduid_api.authuser.from_dict(user_dict)
        self._logger.debug("AuthUser: {!r}".format(self._user))
        self._authstore.add_authuser(self._user)

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
        if isinstance(self._request.token, AddOATHTokenRequest):
            if self._status:
                key_uri = self._request.token.key_uri(self.aead)
                buf = StringIO.StringIO()
                qrcode.make(key_uri).save(buf)
                self._logger.info("Created authuser with id {!r}, credential id {!r}".format(self._user.user_id,
                                                                                             self._token_id))
                res['OATH'] = {'user_id': self._user.user_id,
                               'hmac_key': self.aead.secret,
                               'key_uri': key_uri,
                               'qr_png': buf.getvalue().encode('base64'),
                               }
        res['nonce'] = self._request.nonce  # Copy nonce (request id) from request to response
        return res

    def _get_oath_aead(self):
        """
        """
        self.aead = OATHAEAD(self._logger, self._config)


def add_token(req, authstore, logger, config):
    """
    Add a new token to the API auth system.

    :param req: The parsed add-request
    :param authstore: AuthUsers database
    :param logger: Logger
    :param config: Configuration

    :type req: MFAAddRequest
    :type authstore: eduid_api.authstore.APIAuthStore
    :type logger: eduid_api.log.EduIDAPILogger
    :type config: eduid_api.config.EduIDAPIConfig
    :return: Resppnse dict
    :rtype: dict
    """
    action = AddTokenAction(req, authstore, logger, config)
    action.add_to_authbackend()
    action.add_to_authstore()
    return action.response()
