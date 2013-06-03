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

import logging
import logging.handlers
import cherrypy

class EduIDAPILogger():
    """
    Simple class to do logging in a unified way.
    """

    def __init__(self, myname, context = '', syslog = True, debug = False):
        """
        :params myname: string with name of application
        :params context: string with auxillary data to appear in all audit log messages
        :params syslog: boolean, log to syslog or not?
        :params debug: boolean, controls log verbosity
        """
        self.context = context

        self.logger = logging.getLogger(myname)
        if debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
        if syslog:
            syslog_h = logging.handlers.SysLogHandler()
            formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
            syslog_h.setFormatter(formatter)
            self.logger.addHandler(syslog_h)

    def audit(self, data):
        """
        Audit log data.
        :params data: Audit data as string
        """
        self.logger.info("AUDIT: {context}, {data}".format(context = self.context, data = data))

    def warning(self, msg):
        """
        Log a warning.

        :params msg: Error message as string
        """
        self.logger.warning(msg)

    def error(self, msg, traceback=False):
        """
        Log an error message, additionally appending a traceback.

        :params msg: Error message as string
        :params traceback: Append a traceback or not, True or False
        """
        self.logger.error(msg, exc_info=traceback)
        # get error messages into the cherrypy error log as well
        cherrypy.log.error(msg)

    def set_context(self, context):
        """
        Set data to be included in all future audit logs.
        """
        # XXX this might not be thread safe! Must test if logging is mangled with
        # concurrent authentication requests for different users/from different addresses.
        # Potential solution would be to store context info in cherrypy request object instead,
        # since documentation actually says it can be used like that.
        self.context = ', '.join([k + '=' + v for (k, v) in context.items()])

