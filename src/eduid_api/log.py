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

import sys
import logging
import logging.handlers
import cherrypy


class EduIDAPILogger():
    """
    Simple class to do logging in a unified way.
    """

    def __init__(self, myname, context = '', syslog = True, debug = False):
        """
        :param myname: name of application
        :param context: auxillary data to appear in all audit log messages
        :param syslog: log to syslog or not?
        :param debug: controls log verbosity
        :type myname: basestring
        :type context: basestring
        :type syslog: bool
        :type debug: bool
        """
        self.context = context

        self.logger = logging.getLogger(myname)
        if debug:
            self.logger.setLevel(logging.DEBUG)
            import sys
            sys.stderr.write("DEBUG")
            # log to stderr when debugging
            formatter = logging.Formatter('%(asctime)s %(name)s %(threadName)s: %(levelname)s %(message)s')
            stream_h = logging.StreamHandler(sys.stderr)
            stream_h.setFormatter(formatter)
            self.logger.addHandler(stream_h)
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
        :param data: Audit data
        :type data: basestring
        """
        self.logger.info("AUDIT: {context}, {data}".format(context = self.context, data = data))

    def debug(self, msg):
        """
        Log a debug message.

        :param msg: Debug message
        :type msg: basestring
        """
        self.logger.debug(msg)

    def info(self, msg):
        """
        Log an informational message.

        :param msg: message
        :type msg: basestring
        """
        self.logger.info(msg)

    def warning(self, msg):
        """
        Log a warning.

        :param msg: Error message
        :type msg: basestring
        """
        self.logger.warning(msg)

    def error(self, msg, traceback=False):
        """
        Log an error message, additionally appending a traceback.

        :param msg: Error message
        :param traceback: Append a traceback or not, True or False
        :type msg: basestring
        """
        self.logger.error(msg, exc_info=traceback)
        # get error messages into the cherrypy error log as well
        cherrypy.log.error(msg)

    def set_context(self, context):
        """
        Set data to be included in all future audit logs.
        :param context: Dict with key-value pairs to make context from.
        :type context: dict
        """
        # XXX this might not be thread safe! Must test if logging is mangled with
        # concurrent authentication requests for different users/from different addresses.
        # Potential solution would be to store context info in cherrypy request object instead,
        # since documentation actually says it can be used like that.
        self.context = ', '.join([k + '=' + v for (k, v) in context.items()])
