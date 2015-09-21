#!/usr/bin/python
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
eduID API backend

This is a network service that processes API requests from clients.

See the README.rst file for a more in-depth description.
"""

import os
import sys
import bson
import argparse

import pymongo
import cherrypy
import simplejson

import eduid_api
from eduid_api.common import EduIDAPIError

from eduid_am.tasks import update_attributes
from eduid_am.celery import celery

default_config_file = "/opt/eduid/etc/eduid_api.ini"
default_debug = False


def parse_args():
    """
    Parse the command line arguments
    """
    parser = argparse.ArgumentParser(description = "eduID API backend server",
                                     add_help = True,
                                     formatter_class = argparse.ArgumentDefaultsHelpFormatter,
                                     )
    parser.add_argument('-c', '--config-file',
                        dest='config_file',
                        default=default_config_file,
                        help='Config file',
                        metavar='PATH',
                        )

    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true', default=default_debug,
                        help='Enable debug operation',
                        )

    return parser.parse_args()


class APIBackend(object):
    """
    The CherryPy application object.
    """

    def __init__(self, logger, db, authstore, config, expose_real_errors=False):
        """
        :param logger: logging object (for audit logs)
        :param db: database object
        :param authstore: Credential store
        :param config: config object
        :param expose_real_errors: mask errors or expose them (for devel/debug/test)
        :type logger: eduid_api.log.EduIDAPILogger
        :type db: eduid_api.db.EduIDAPIDB | None
        :type authstore: eduid_api.authstore.APIAuthStore | None
        :type config: eduid_api.config.EduIDAPIConfig
        :type expose_real_errors: bool

        """
        self.logger = logger
        self.db = db
        self.authstore = authstore
        self.config = config
        self.expose_real_errors = expose_real_errors
        # make pylint happy
        self.remote_ip = 'UNKNOWN'

        cherrypy.config.update({'request.error_response': self.handle_error,
                                'error_page.default': self.error_page_default,
                                })

    @cherrypy.expose
    def mfa_add(self, **data):
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
        self.remote_ip = cherrypy.request.remote.ip

        request = data.get('request')
        self.logger.debug("Extra debug: mfa_add request:{!r}".format(data))

        # Parse request and handle any errors
        fun = lambda: eduid_api.mfa_add.MFAAddRequest(request, self.remote_ip, self.logger, self.config)
        success, req = self._parse_request(fun, 'mfa_add')
        if not success:
            return req

        fun = lambda: eduid_api.mfa_add.add_token(req, self.authstore, self.logger, self.config)
        response = self._execute(fun, 'mfa_add')

        return response.to_string(remote_ip = self.remote_ip)

    @cherrypy.expose
    def mfa_auth(self, request=None):
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
        self.remote_ip = cherrypy.request.remote.ip

        # Parse request and handle any errors
        fun = lambda: eduid_api.mfa_auth.MFAAuthRequest(request, self.remote_ip, self.logger, self.config)
        success, req = self._parse_request(fun, 'mfa_auth')
        if not success:
            return req

        fun = lambda: eduid_api.mfa_auth.authenticate(req, self.authstore, self.logger, self.config)
        response = self._execute(fun, 'mfa_auth')

        return response.to_string(remote_ip = self.remote_ip)

    @cherrypy.expose
    def aead_gen(self, request=None):
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
        self.remote_ip = cherrypy.request.remote.ip

        # Parse request and handle any errors
        fun = lambda: eduid_api.aead_gen.AEADGenRequest(request, self.remote_ip, self.logger, self.config)
        success, req = self._parse_request(fun, 'aead_gen')
        if not success:
            return req

        fun = lambda: eduid_api.aead_gen.AEADGenAction(req, self.logger, self.config).response()
        response = self._execute(fun, 'aead_gen')

        return response.to_string(remote_ip = self.remote_ip)

    def _parse_request(self, fun, name):
        """
        Generic request parser wrapper to handle errors during parsing in a uniform way.

        :param fun: Function that will parse the request
        :type fun: callable
        :return: Parsed data
        """
        self.logger.info("Parsing {!s} request from {!r}".format(name, self.remote_ip))
        log_context = {'client': self.remote_ip,
                       'req': name,
                       }
        self.logger.set_context(log_context)

        try:
            req = fun()
            if not req.signing_key:
                self.logger.info("Could not decrypt/authenticate request from {!r}".format(self.remote_ip))
                cherrypy.response.status = 403
                # Don't disclose anything about our internal issues
                return False, None
            self.logger.debug("Parsed and authenticated {!s} request:\n{!r}".format(name, req))
            return True, req
        except EduIDAPIError as ex:
            self.logger.info("Parsing {!s} failed: {!s}".format(name, ex.reason))
            res = eduid_api.response.ErrorResponse(ex.reason, self.logger, self.config)
            return False, res.to_string(remote_ip = self.remote_ip)

    def _execute(self, fun, name):
        """
        Generic request parser wrapper to handle errors during execution in a uniform way.

        :param fun: Function that will execute a previously parsed request
        :type fun: callable
        :return: eduid_api.response.BaseResponse
        """
        try:
            response = fun()
            return eduid_api.response.BaseResponse(response, self.logger, self.config)
        except EduIDAPIError as ex:
            self.logger.info("Executing {!s} failed: {!s}".format(name, ex.reason))
            return eduid_api.response.ErrorResponse(ex.reason, self.logger, self.config)

    def handle_error(self):
        """
        Function called by CherryPy when there is an unhandled exception processing a request.

        Display a 'fail whale' page (error.html), and log the error in a way that makes
        post-mortem analysis in Sentry as easy as possible.
        """
        self.logger.debug("handle_error() invoked")
        cherrypy.response.status = 500
        res = eduid_api.response.ErrorResponse('Server Error', self.logger, self.config)
        try:
            cherrypy.response.body = res.to_string(remote_ip = self.remote_ip)
        except EduIDAPIError as exc:
            # This error is typically EduIDAPIError("No API Key found - can't encrypt response")
            cherrypy.response.body = str(exc.reason) + "\n"

    def error_page_default(self, status, message, traceback, version):
        """
        Function called by CherryPy when there is an unhandled exception processing a request.

        Display a 'fail whale' page (error.html), and log the error in a way that makes
        post-mortem analysis in Sentry as easy as possible.

        :param status: HTML error code like '404 Not Found'
        :param message: HTML error message
        :param traceback: traceback of error
        :param version: cherrypy version

        :type status: string
        :type message: string
        :type traceback: string
        :type version: string
        :rtype: string
        """
        self.logger.debug("error_page_default() invoked, status={!r}, message={!r}".format(status, message))
        cherrypy.response.status = 500
        res = eduid_api.response.ErrorResponse('Server Error 2', self.logger, self.config)
        cherrypy.response.body = res.to_string(remote_ip = self.remote_ip)


def main(myname = 'eduid_api'):
    """
    Initialize everything and start the API backend.

    :param myname: Name of application, for logging purposes.
    :type myname: basestring
    """
    args = parse_args()

    # initialize various components
    config = eduid_api.config.EduIDAPIConfig(args.config_file, args.debug)
    logger = eduid_api.log.EduIDAPILogger(myname, config)
    if config.mongodb_uri:
        db = eduid_api.db.EduIDAPIDB(config.mongodb_uri)
        authstore = eduid_api.authstore.APIAuthStoreMongoDB(config.mongodb_uri, logger)
    else:
        # Some functions, such as aead_gen, does not require mongodb.
        logger.info("No mongodb_uri configured")
        db = None
        authstore = None

    if config.yhsm:
        logger.info("YubiHSM: {!r}".format(config.yhsm.version.sysinfo))

    cherry_conf = {'server.socket_host': config.listen_addr,
                   'server.socket_port': config.listen_port,
                   # enables X-Forwarded-For, since BCP is to run this server
                   # behind a webserver that handles SSL
                   'tools.proxy.on': True,
                   'request.show_tracebacks': config.debug,
                   }
    if config.logdir:
        cherry_conf['log.access_file'] = os.path.join(config.logdir, 'access.log')
        cherry_conf['log.error_file'] = os.path.join(config.logdir, 'error.log')
    else:
        sys.stderr.write("NOTE: Config option 'logdir' not set.\n")

    if config.server_cert and config.server_key:
        cherry_conf['server.ssl_module'] = config.ssl_adapter
        cherry_conf['server.ssl_certificate'] = config.server_cert
        cherry_conf['server.ssl_private_key'] = config.server_key
        cherry_conf['server.ssl_certificate_chain'] = config.cert_chain

    cherrypy.config.update(cherry_conf)

    if config.broker_url is not None:
        celery.conf.update(BROKER_URL=config.broker_url)
    else:
        logger.warning("Config option 'broker_url' not set. AMQP notifications will not work.")

    cherrypy.quickstart(APIBackend(logger, db, authstore, config))

if __name__ == '__main__':
    try:
        progname = os.path.basename(sys.argv[0])
        if main(progname):
            sys.exit(0)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
