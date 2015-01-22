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
import simplejson
from eduid_api.common import EduIDAPIError


class BaseRequest():
    """
    Base authentication/revocation request.

    :param json: JSON encoded data
    :param logger: logging object
    :param config: config object

    :type json: basestring
    :type logger: eduid_api.log.EduIDAPILogger
    :type config: eduid_api.config.EduIDAPIConfig
    """

    def __init__(self, json, logger, config):

        try:
            body = simplejson.loads(json)
        except Exception:
            logger.error("Failed parsing JSON body :\n{!r}\n-----\n".format(json), traceback=True)
            raise EduIDAPIError("Failed parsing request")

        assert(isinstance(body, dict))

        if body.get('version', 1) is not 1:
            # really handle missing version below
            raise EduIDAPIError("Unknown request version : {!r}".format(body['version']))

        for req_field in ['version']:
            if req_field not in body:
                raise EduIDAPIError("No {!r} in request".format(req_field))

        self._parsed_req = body

    def __repr__(self):
        return ('<{} @{:#x}>'.format(
            self.__class__.__name__,
            id(self),
        ))


def check_and_decrypt(request, remote_ip, name, config, logger):
    """
    Decrypt a request and check it's signature and authorize the sender.

    :param request: The raw request
    :param remote_ip: IP address of client
    :param name: The name of the function invoked
    :param logger: logging object (for audit logs)
    :param config: config object
    :type request: basestring
    :type remote_ip: basestring
    :type name: basestring
    :type logger: eduid_api.log.EduIDAPILogger
    :type config: eduid_api.config.EduIDAPIConfig
    """
    try:

        logger.debug("FREDRIK: JWE from {!r}".format(request))

        jwe = jose.deserialize_compact(request)
        keys = config.keys.lookup_by_ip(remote_ip)

        if not len(keys):
            logger.info("No API keys found for IP address {!r}".format(remote_ip))
            return False

        decrypted = None
        for key in keys:
            if not key.keytype == 'jose':
                logger.debug("Ignoring key {!r}".format(key))
                continue
            logger.debug("Trying to decrypt request with key {!r}".format(key))
            try:
                logger.debug("FREDRIK: JWE {!r} from {!r}, JWK {!r}".format(jwe, request, key.jwk))
                decrypted = jose.decrypt(jwe, key.jwk, expiry_seconds = key.expiry_seconds)
            except jose.Expired:
                logger.warning("Request encrypted with key {!r} has expired".format(key))
            except jose.Error:
                pass

        return decrypted
    except Exception:
        logger.error("check_and_decrypt failed", traceback = True)
        return False
