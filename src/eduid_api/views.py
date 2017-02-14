# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Blueprint, current_app, request, abort

import eduid_api
from eduid_api.common import EduIDAPIError


__author__ = 'ft'

eduid_api_views = Blueprint('eduid_api', __name__, url_prefix='')


def _get_remote_ip():
    if request.headers.getlist('X-Forwarded-For'):
        return request.headers.getlist('X-Forwarded-For')[0]
    return request.remote_addr


def _parse_request(config, fun, name):
    """
    Generic request parser wrapper to handle errors during parsing in a uniform way.

    :param fun: Function that will parse the request
    :type fun: callable
    :return: Parsed data
    """
    _remote_ip = _get_remote_ip()
    current_app.logger.info("Parsing {!s} request from {!r}".format(name, _remote_ip))

    try:
        req = fun()
        if not req.signing_key:
            current_app.logger.info("Could not decrypt/authenticate request from {!r}".format(_remote_ip))
            abort(403)
        current_app.logger.debug("Parsed and authenticated {!s} request:\n{!r}".format(name, req))
        return True, req
    except EduIDAPIError as ex:
        current_app.logger.info("Parsing {!s} failed: {!s}".format(name, ex.reason))
        res = eduid_api.response.ErrorResponse(ex.reason)
        return False, res.to_string(remote_ip = _remote_ip)


def _execute(fun, name):
    """
    Generic request parser wrapper to handle errors during execution in a uniform way.

    :param fun: Function that will execute a previously parsed request
    :type fun: callable
    :return: eduid_api.response.BaseResponse
    """
    try:
        response = fun()
        return eduid_api.response.BaseResponse(response)
    except EduIDAPIError as ex:
        current_app.logger.info("Executing {!s} failed: {!s}".format(name, ex.reason))
        return eduid_api.response.ErrorResponse(ex.reason)


@eduid_api_views.route('/mfa_add', methods=['POST'])
def mfa_add():
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

    :param request: JSON formatted request
    :type request: str
    """
    _remote_ip = _get_remote_ip()
    data = request.get_json()
    if type(data) is not dict:
        raise ValueError("request must be a dict")
    _request = data.get('request')

    current_app.logger.debug("Extra debug: mfa_add request:{!r}".format(data))

    def mfa_add_request():
        return eduid_api.mfa_add.MFAAddRequest(_request, _remote_ip, current_app.logger, current_app.config)

    success, req = _parse_request(current_app.config, mfa_add_request, 'mfa_add')
    if not success:
        return req

    def add_token():
        return eduid_api.mfa_add.add_token(req,
                                           current_app.state.authstore,
                                           current_app.logger,
                                           current_app.config,
                                           )
    response = _execute(add_token, 'mfa_add')

    return response.to_string(remote_ip = _remote_ip)


@eduid_api_views.route('/mfa_auth', methods=['POST'])
def mfa_auth():
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


    :param request: JSON formatted request
    :type request: str
    """
    _remote_ip = _get_remote_ip()
    data = request.get_json()
    if type(data) is not dict:
        raise ValueError("request must be a dict")
    _request = data.get('request')

    # Parse request and handle any errors
    def mfa_auth_request():
        return eduid_api.mfa_auth.MFAAuthRequest(_request,
                                                 _remote_ip,
                                                 current_app.logger,
                                                 current_app.config,
                                                 )
    success, req = _parse_request(current_app.config, mfa_auth_request, 'mfa_auth')
    if not success:
        return req

    def authenticate():
        return eduid_api.mfa_auth.authenticate(req,
                                               current_app.mystate.authstore,
                                               current_app.logger,
                                               current_app.config,
                                               )
    response = _execute(authenticate, 'mfa_auth')

    return response.to_string(remote_ip = _remote_ip)


@eduid_api_views.route('/mfa_test', methods=['POST'])
def mfa_test():
    """
    Test communication with the API.

    Example request POSTed to /mfa_auth:

        {
            "version":    1,
            "nonce":      "18e4909c157f670169c7",
        }

    Example response:

        {
            "nonce": "18e4909c157f670169c7",
            "status": "OK"
        }


    :param request: JSON formatted request
    :type request: str
    """
    _remote_ip = _get_remote_ip()
    data = request.form
    current_app.logger.debug('TEST2: {!r}'.format(data))
    _request = data.get('request')

    # Parse request and handle any errors
    def mfa_test_request():
        return eduid_api.mfa_test.MFATestRequest(_request,
                                                 _remote_ip,
                                                 current_app.logger,
                                                 )
    success, req = _parse_request(current_app.config, mfa_test_request, 'mfa_auth')
    if not success:
        return req

    def do_test():
        return eduid_api.mfa_test.test(req, current_app.logger)

    response = _execute(do_test, 'mfa_auth')

    return response.to_string(remote_ip = _remote_ip)


@eduid_api_views.route('/aead_gen', methods=['POST'])
def aead_gen():
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

    :param request: JSON formatted request
    :type request: str
    """
    _remote_ip = _get_remote_ip()
    data = request.get_json()
    if type(data) is not dict:
        raise ValueError("request must be a dict")
    _request = data.get('request')

    # Parse request and handle any errors
    def aead_gen_request():
        return eduid_api.aead_gen.AEADGenRequest(_request,
                                                 _remote_ip,
                                                 current_app.logger,
                                                 current_app.config)
    success, req = _parse_request(current_app.config, aead_gen_request, 'aead_gen')
    if not success:
        return req

    def aead_gen_action():
        return eduid_api.aead_gen.AEADGenAction(req,
                                                current_app.logger,
                                                current_app.config).response()
    response = _execute(aead_gen_action, 'aead_gen')

    return response.to_string(remote_ip = _remote_ip)


@eduid_api_views.route('/ping', methods=['GET', 'POST'])
def ping():
    return 'pong'
