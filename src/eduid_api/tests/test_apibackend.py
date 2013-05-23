#!/usr/bin/python
#
# Copyright (c) 2013 NORDUnet A/S
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
Test the eduID API backend.
"""

import os
import unittest
import pkg_resources

import cherrypy
import cptestcase
import simplejson as json

import eduid_api
from eduid_api.eduid_apibackend import APIBackend
from eduid_api.log import EduIDAPILogger

class TestAuthBackend(cptestcase.BaseCherryPyTestCase):

    def setUp(self):
        debug = False
        datadir = pkg_resources.resource_filename(__name__, 'data')
        self.config_file = os.path.join(datadir, 'test_config.ini')
        self.config = eduid_api.config.EduIDAPIConfig(self.config_file, debug)
        self.logger = eduid_api.log.EduIDAPILogger('test_apibackend', syslog=False)
        try:
            self.db = eduid_api.db.EduIDAPIDB(self.config.mongodb_uri)
        except Exception:
            # will skip tests that require mongodb
            self.db = None

        self.apibackend = APIBackend(self.logger, self.db, self.config, expose_real_errors=True)

        cherrypy.tree.mount(self.apibackend, '/')
        cherrypy.engine.start()

    def tearDown(self):
        cherrypy.engine.exit()

    def test_bad_request(self):
        """
        Verify bad requests are rejected
        """
        response = self.request('/')
        self.assertEqual(response.output_status, '404 Not Found')

    def test_add_raw_request_wrong_version(self):
        """
        Verify add_raw request with wrong version is rejected
        """
        a = {'add_raw': {},
             'version': 9999,
             }
        j = json.dumps(a)
        response = self.request('/add_raw', request=j, return_error=True)
        self.assertIn('Unknown request version : 9999', response.body[0])

        # try again with blinding
        self.apibackend.expose_real_errors = False
        response = self.request('/add_raw', request=j, return_error=True)
        self.assertEqual(response.output_status, '500 Internal Server Error')

    def test_add_raw_missing_data(self):
        """
        Verify add_raw request with missing data is rejected
        """
        for req_field in ['data']:
            a = {'add_raw': {'foo': 'bar'},
                 'version': 1,
                 }
            if req_field in a['add_raw']:
                del a['add_raw'][req_field]
            j = json.dumps(a)
            response = self.request('/add_raw', request=j, return_error=True)
            self.assertIn("No '{!s}' in request".format(req_field), response.body[0])

    def test_add_raw_request1(self):
        """
        Verify correct add_raw request
        """
        if self.db is None:
            raise unittest.SkipTest("requires accessible MongoDB server on {!s}".format(
                    self.config.mongodb_uri))

        raise unittest.SkipTest("test disabled because AMQP server can't be mocked at this time")

        a = {'add_raw':
                 {'data': {'email': 'ft@example.net',
                           'verified': True,
                           },
                  },
             'version': 1,
             }
        j = json.dumps(a)
        response = self.request('/add_raw', request=j, return_error=True)
        res = json.loads(response.body[0])
        expected = {'add_raw':
                        {'version': 1,
                         'success': True,
                         }
                    }
        self.assertEqual(res, expected)
