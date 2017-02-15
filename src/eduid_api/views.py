# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Blueprint, current_app, request

import eduid_api
from eduid_api.decorators import MFAAPIParseAndVerify, MFAAPIResponse
from eduid_api.aead_gen import AEADGenRequest
from eduid_api.mfa_add import MFAAddRequest
from eduid_api.mfa_auth import MFAAuthRequest
from eduid_api.mfa_test import MFATestRequest

__author__ = 'ft'

eduid_api_views = Blueprint('eduid_api', __name__, url_prefix='')


@eduid_api_views.route('/mfa_add', methods=['POST'])
@MFAAPIParseAndVerify('mfa_add', MFAAddRequest)
@MFAAPIResponse('mfa_add')
def mfa_add(req):
    """
    Create a new MultiFactor Authentication token for someone.

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

    Example response:

        {
            "OATH": {
                "user_id": "54de24ca8a5da50011e23b41",
                "hmac_key": "1cca0f7656ef50f182bc90fd8c0bb43140924a78",
                "key_uri": "otpauth://totp/TestIssuer:user@example.org?secret=DTFA6...GFAJESTY&issuer=TestIssuer",
                "qr_png": "iVBO...ORK5CYII=\n",
            },
            "nonce": "74b4a9a07084799548e5",
            "status": "OK"
        }

    The 'nonce' has nothing to do with the token - it allows the API client to
    ensure that a response is in fact related to a specific request.

    :param req: Instance of decrypted and parsed request
    :type req: MFAAddRequest

    :returns: Request and response
    """
    res = eduid_api.mfa_add.add_token(req,
                                      current_app.state.authstore,
                                      current_app.logger,
                                      current_app.config,
                                      )
    return req, res


@eduid_api_views.route('/mfa_auth', methods=['POST'])
@MFAAPIParseAndVerify('mfa_auth', MFAAuthRequest)
@MFAAPIResponse('mfa_auth')
def mfa_auth(req):
    """
    Authenticate with MFA (Multi Factor Authentication).

    Example request POSTed to /mfa_auth:

        {
            "version":    1,
            "nonce":      "18e4909c157f670169c7",
            "OATH": {
                "user_id": "54e20dec8a5da5000d35083e",
                "user_code": "123456"
            }
        }

    Example response:

        {
            "OATH": {
                "authenticated": true
            },
            "nonce": "18e4909c157f670169c7",
            "status": "OK"
        }

    :param req: Instance of decrypted and parsed request
    :type req: MFAAuthRequest

    :returns: Request and response
    """
    res = eduid_api.mfa_auth.authenticate(req,
                                          current_app.mystate.authstore,
                                          current_app.logger,
                                          current_app.config,
                                          )
    current_app.logger.debug('Authentication result: {!r}'.format(res))
    return req, res


@eduid_api_views.route('/mfa_test', methods=['POST'])
@MFAAPIParseAndVerify('mfa_test', MFATestRequest)
@MFAAPIResponse('mfa_test')
def mfa_test(req):
    """
    Test communication with the API.

    Example decrypted request POSTed to /mfa_test:

        {
            "version":    1,
            "nonce":      "18e4909c157f670169c7",
        }

    Example response:

        {
            "nonce": "18e4909c157f670169c7",
            "mfa_test_status": "OK"
        }


    :param req: Instance of decrypted and parsed request
    :type req: eduid_api.mfa_test.MFATestRequest

    :returns: Request and response
    """
    return req, eduid_api.mfa_test.test(req, current_app.logger)


@eduid_api_views.route('/aead_gen', methods=['POST'])
@MFAAPIParseAndVerify('aead_gen', AEADGenRequest)
@MFAAPIResponse('mfa_test')
def aead_gen(req):
    """
    Create a new AEAD, probably for a new OATH token.

    Example request POSTed to /aead_gen:

        {
            "version":    1,
            "nonce":      "74b4a9a07084799548e5",
            "plaintext":  True,
            "length":     20
        }

    If 'plaintext' is True, the actual plaintext of the AEAD is returned (key named
    'secret' to avoid inclusion in Sentry reports). This is necessary when creating
    OATH AEADs since the actual secret has to be provisioned into the user's token,
    but is optional in this API in case some future use case does not require it.

    :param req: Instance of decrypted and parsed request
    :type req: AEADGenRequest

    :returns: Request and response
    """
    res = eduid_api.aead_gen.make_aead(req,
                                       current_app.logger,
                                       current_app.config,
                                       )
    return req, res


@eduid_api_views.route('/ping', methods=['GET', 'POST'])
def ping():
    return 'pong'
