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


class BaseRequest():
    """
    Base authentication/revocation request.

    :param json: JSON formatted request
    :param top_node: 'add_raw' - part of JSON request to parse
    :param logger: logging object
    :type json: basestring
    :type top_node: basestring
    :type logger: eduid_api.log.EduIDAPILogger
    """
    def __init__(self, json, top_node, logger):
        self.top_node = top_node
        try:
            body = simplejson.loads(json)
        except Exception:
            logger.error("Failed parsing JSON body :\n{!r}\n-----\n".format(json), traceback=True)
            raise EduIDAPIError("Failed parsing request")

        assert(isinstance(body, dict))

        if body.get('version', 1) is not 1:
            # really handle missing version below
            raise EduIDAPIError("Unknown request version : {!r}".format(body['version']))

        for req_field in ['version', top_node]:
            if req_field not in body:
                raise EduIDAPIError("No {!r} in request".format(req_field))

        req = body[top_node]

        self._parsed_req = req

    def __repr__(self):
        return ('<{} @{:#x}: action={action!r}'.format(
            self.__class__.__name__,
            id(self),
            action=self.top_node,
        ))


class AddRawRequest(BaseRequest):

    """
    Parse JSON body into 'add raw' request object.

    Example (request) body :

    {
        "add_raw": {
            "data": {
                "email": "ft@example.net",
                "verified": true
            }
        },
        "version": 1
    }
    """

    def __init__(self, json, top_node, logger):
        """
        :param json: JSON formatted request
        :param top_node: 'add_raw' - part of JSON request to parse
        :param logger: logging object
        :type json: basestring
        :type top_node: basestring
        :type logger: eduid_api.log.EduIDAPILogger
        """
        BaseRequest.__init__(self, json, top_node, logger)

        for req_field in ['data']:
            if req_field not in self._parsed_req:
                raise EduIDAPIError("No {!r} in request".format(req_field))

        for req_data_field in ['email']:
            if req_data_field not in self._parsed_req['data']:
                raise EduIDAPIError("No {!r} in request[data]".format(req_data_field))

        self._data = self._parsed_req['data']

        if '_id' in self._data:
            self._data['_id'] = bson.ObjectId(self._data['_id'])

    def data(self):
        """
        Return the 'data' element from the request.
        """
        return self._data


class APIBackend(object):
    """
    The CherryPy application object.
    """

    def __init__(self, logger, db, config, expose_real_errors=False):
        """
        :param logger: logging object (for audit logs)
        :param db: database object
        :param config: config object
        :param expose_real_errors: mask errors or expose them (for devel/debug/test)
        :type logger: eduid_api.log.EduIDAPILogger
        :type db: eduid_api.db.EduIDAPIDB
        :type config: eduid_api.config.EduIDAPIConfig
        :type expose_real_errors: bool

        """
        self.logger = logger
        self.db = db
        self.config = config
        self.expose_real_errors = expose_real_errors
        # make pylint happy
        self.remote_ip = 'UNKNOWN'

    @cherrypy.expose
    def add_raw(self, request=None):
        """
        Add an entry to the user database.

        :param request: JSON formatted request
        :type request: basestring
        """
        self.remote_ip = cherrypy.request.remote.ip

        if not self.remote_ip in self.config.add_raw_allow:
            self.logger.error("Denied add_raw request from {} not in add_raw_allow ({})".format(
                self.remote_ip, self.config.add_raw_allow))
            cherrypy.response.status = 403
            # Don't disclose anything about our internal issues
            return None

        log_context = {'client': self.remote_ip,
                       'req': 'add_raw',
                       }
        self.logger.set_context(log_context)

        # Parse request
        req = AddRawRequest(request, 'add_raw', self.logger)

        docu = req.data()
        result = False
        data = ''

        # check if email already exists in the database (NB. The eduid_api database, not eduid_am).
        existing = self.db.users.find({'email': docu['email']})
        if existing.count() > 1:
            data = 'multiple records found for email {!r}'.format(docu['email'])
        elif existing.count() and existing[0]['_id'] != docu.get('_id'):
            data = 'email {!r} already exist (_id {!s})'.format(docu['email'], existing[0]['_id'])
        else:
            # save in mongodb
            try:
                self.db.users.save(docu, manipulate=True, safe=True)
            except pymongo.errors.PyMongoError as exception:
                data = str(exception)
            else:
                data = 'OK'
                result = True

        docu_id = str(docu.get('_id'))
        self.logger.audit("result={!s},data={!s},_id={!s}".format(result, data, docu_id))

        if type(result) == int:
            cherrypy.response.status = result
            # Don't disclose anything on our internal failures
            return None

        if result:
            # Send the signal to the attribute manager so it can update
            # this user's attributes in the IdP
            try:
                update_attributes.delay('eduid_api', str(docu_id))
            except Exception as exception:
                self.logger.error("Failed signalling update_attributes : {!s}".format(exception), traceback=True)
                # XXX maybe the document should be removed and a failure returned instead?
                data = 'Stored, but update_attributes failed'

        # _id should be set now, since manipulate=True
        response = {'add_raw_response': {'version': 1,
                                         'success': result,
                                         'data': data,
                                         '_id': docu_id,
                                         }
                    }
        return "{}\n".format(simplejson.dumps(response, sort_keys=True, indent=4))


def main(myname = 'eduid_api'):
    """
    Initialize everything and start the API backend.

    :param myname: Name of application, for logging purposes.
    :type myname: basestring
    """
    args = parse_args()

    # initialize various components
    config = eduid_api.config.EduIDAPIConfig(args.config_file, args.debug)
    logger = eduid_api.log.EduIDAPILogger(myname)
    db = eduid_api.db.EduIDAPIDB(config.mongodb_uri)

    cherry_conf = {'server.socket_host': config.listen_addr,
                   'server.socket_port': config.listen_port,
                   # enables X-Forwarded-For, since BCP is to run this server
                   # behind a webserver that handles SSL
                   'tools.proxy.on': True,
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

    cherrypy.quickstart(APIBackend(logger, db, config))

if __name__ == '__main__':
    try:
        progname = os.path.basename(sys.argv[0])
        if main(progname):
            sys.exit(0)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
