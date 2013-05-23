# -*- coding: utf-8 -*-
#
# CherryPy application test case recipe downloaded from
#
#  https://bitbucket.org/Lawouach/cherrypy-recipes/raw/ \
#    50aff88dc4e24206518ec32e1c32af043f2729da/testing/unit/serverless/cptestcase.py
#
# Copyright (c) 2011-2012, Sylvain Hellegouarch
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright notice,
#       this list of conditions and the following disclaimer in the documentation
#       and/or other materials provided with the distribution.
#     * Neither the name of Sylvain Hellegouarch nor the names of his contributors
#       may be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
from StringIO import StringIO
import unittest
import urllib

import cherrypy

# Not strictly speaking mandatory but just makes sense
cherrypy.config.update({'environment': "test_suite"})

# This is mandatory so that the HTTP server isn't started
# if you need to actually start (why would you?), simply
# subscribe it back.
cherrypy.server.unsubscribe()

__all__ = ['BaseCherryPyTestCase']

def _make_host(hostport):
    # todo: add v6
    host, port, = hostport.split(':')
    return cherrypy.lib.httputil.Host(host, int(port), "")

class BaseCherryPyTestCase(unittest.TestCase):
    def request(self, path='/', method='GET', app_path='', scheme='http',
                proto='HTTP/1.1', data=None, headers=None, return_error=False,
                local_hp='127.0.0.1:50000', remote_hp='127.0.0.1:50001', **kwargs):
        """
        CherryPy does not have a facility for serverless unit testing.
        However this recipe demonstrates a way of doing it by
        calling its internal API to simulate an incoming request.
        This will exercise the whole stack from there.

        Remember a couple of things:

        * CherryPy is multithreaded. The response you will get
          from this method is a thread-data object attached to
          the current thread. Unless you use many threads from
          within a unit test, you can mostly forget
          about the thread data aspect of the response.

        * Responses are dispatched to a mounted application's
          page handler, if found. This is the reason why you
          must indicate which app you are targetting with
          this request by specifying its mount point.

        You can simulate various request settings by setting
        the `headers` parameter to a dictionary of headers,
        the request's `scheme` or `protocol`.

        .. seealso: http://docs.cherrypy.org/stable/refman/_cprequest.html#cherrypy._cprequest.Response
        """
        # This is a required header when running HTTP/1.1
        h = {'Host': '127.0.0.1'}

        if headers is not None:
            h.update(headers)

        # If we have a POST/PUT request but no data
        # we urlencode the named arguments in **kwargs
        # and set the content-type header
        if method in ('POST', 'PUT') and not data:
            data = urllib.urlencode(kwargs)
            kwargs = None
            h['content-type'] = 'application/x-www-form-urlencoded'

        # If we did have named arguments, let's
        # urlencode them and use them as a querystring
        qs = None
        if kwargs:
            qs = urllib.urlencode(kwargs)

        # if we had some data passed as the request entity
        # let's make sure we have the content-length set
        fd = None
        if data is not None:
            h['content-length'] = '%d' % len(data)
            fd = StringIO(data)

        # Get our application and run the request against it
        app = cherrypy.tree.apps.get(app_path)
        if not app:
            # XXX: perhaps not the best exception to raise?
            raise AssertionError("No application mounted at '%s'" % app_path)

        # Cleanup any previous returned response
        # between calls to this method
        app.release_serving()

        # Let's fake the local and remote addresses
        local = _make_host(local_hp)
        remote = _make_host(remote_hp)

        request, response = app.get_serving(local, remote, scheme, proto)
        try:
            h = [(k, v) for k, v in h.iteritems()]
            response = request.run(method, path, qs, proto, h, fd)
        finally:
            if fd:
                fd.close()
                fd = None

        if response.output_status.startswith('500') and not return_error:
            print response.body
            raise AssertionError("HTTP error: {!s}".format(response.output_status))

        # collapse the response into a bytestring
        response.collapse_body()
        return response
