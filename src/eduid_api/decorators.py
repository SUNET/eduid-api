#  -*- coding: utf-8 -*-
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

from functools import wraps
from flask import current_app, request, abort, g

import eduid_api
from eduid_api.common import EduIDAPIError

# Key to store request instance for use in the response-decorator
_REQ_ATTR = 'eduid_mfaapi_attr'


def _get_remote_ip():
    if request.headers.getlist('X-Forwarded-For'):
        return request.headers.getlist('X-Forwarded-For')[0]
    return request.remote_addr


class MFAAPIParseAndVerify(object):
    """
    Decorator that parses the JOSE signed-and-encrypted requests we receive.

    The decorator takes the name of a request parser class as an argument,
    and will instantiate an object of that class from the verified-and-decrypted
    JSON data. This object is what will be passed to the wrapped function
    as the first (and only) parameter.

    :param name: Name of wrapped function, for logging purposes
    :param req_class: an eduid_api.request.BaseRequest class
    """
    def __init__(self, name, req_class):
        self.name = name
        self.req_class = req_class

    def __call__(self, f):
        """
        Generic request parser wrapper to handle errors during parsing in a uniform way.
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            _remote_ip = _get_remote_ip()
            current_app.logger.info("Parsing {!s} request from {!r}".format(self.name, _remote_ip))

            try:
                data = request.form
                if 'request' in data:
                    req = self.req_class(data['request'], _remote_ip, current_app.logger)
                    current_app.logger.debug("Parsed and authenticated {!s} request:\n{!r}".format(self.name, req))

                    # Store the request in the request context (flask.g) so that we can use it
                    # to encrypt responses in MFAAPIResponse below
                    setattr(g, _REQ_ATTR, req)

                    return f(req, *args, **kwargs)
                abort(401)
            except EduIDAPIError as ex:
                current_app.logger.info("Parsing {!s} failed: {!s}".format(self.name, ex.reason))
                if current_app.config.get('TESTING') is not True:
                    # Calling abort() here hides the real error from the client.
                    c = current_app.config
                    abort(400)
                raise
        return decorated_function


class MFAAPIResponse(object):
    """
    Decorator to sign-and-encrypt data to be sent as responses.

    :param name: Name of wrapped function, for logging purposes
    """
    def __init__(self, name):
        self.name = name

    def __call__(self, f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                response = f(*args, **kwargs)
                req = getattr(g, _REQ_ATTR)
                return eduid_api.response.BaseResponse(response, req).to_string()
            except EduIDAPIError as ex:
                current_app.logger.info("Executing {!s} failed: {!s}".format(self.name, ex.reason))
                req = getattr(g, _REQ_ATTR)
                return eduid_api.response.ErrorResponse(ex.reason, req).to_string()
        return decorated_function
