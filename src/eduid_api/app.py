# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Flask
from eduid_common.api.logging import init_logging
from eduid_common.api.exceptions import init_exception_handlers
from eduid_common.config.parsers.etcd import EtcdConfigParser
from eduid_api.common import EduIDAPIError

import argparse

import eduid_api


__author__ = 'ft'


default_config_file = '/opt/eduid/etc/eduid_api.ini'
default_debug = False


def parse_args():
    """
    Parse the command line arguments
    """
    parser = argparse.ArgumentParser(description = 'eduID API backend server',
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


class MyState(object):

    def __init__(self, app):
        # Init dbs
        self.db = eduid_api.db.EduIDAPIDB(app.config['MONGO_URI'])
        self.authstore = eduid_api.authstore.APIAuthStoreMongoDB(app.config['MONGO_URI'], app.logger)

        # split on comma and strip. cache result.
        tmp_add_raw_allow = str(app.config['ADD_RAW_ALLOW']) # for pylint
        self._parsed_add_raw_allow = \
            [x.strip() for x in tmp_add_raw_allow.split(',')]
        self.keys = eduid_api.keystore.KeyStore(app.config['KEYSTORE_FN'])
        self.keys = eduid_api.keystore.KeyStore(app.config['KEYSTORE_FN'])

        app.logger.info("Loaded keys from {!r}: {!r}".format(app.config['KEYSTORE_FN'], self.keys))
        self._parsed_oath_aead_keyhandle = None
        self.yhsm = None
        kh_str = app.config['OATH_AEAD_KEYHANDLE']
        _yhsm_device = app.config.get('OATH_YHSM_DEVICE')
        if _yhsm_device or kh_str:
            try:
                import pyhsm
                if kh_str:
                    self._parsed_oath_aead_keyhandle = pyhsm.util.key_handle_to_int(kh_str.strip())
                try:
                    self.yhsm = pyhsm.YHSM(device = _yhsm_device)
                    # stir up the pool
                    for _ in range(10):
                        self.yhsm.random(32)
                except pyhsm.exception.YHSM_Error:
                    raise EduIDAPIError('YubiHSM init error')
            except ImportError:
                raise EduIDAPIError("yhsm settings present, but import of pyhsm failed")


def init_eduid_api_app(name, config=None):
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases

    :type name: str
    :type config: dict

    :return: the flask app
    :rtype: flask.Flask
    """
    app = Flask(name, static_folder=None)

    # Load configuration
    app.config.from_object('eduid_api.settings.common')
    app.config.from_envvar('EDUID_API_SETTINGS', silent=True)
    if config:
        app.config.update(config)

    common_parser = EtcdConfigParser('/eduid/webapp/common/')
    app_parser = EtcdConfigParser('/eduid/webapp/{!s}/'.format(name))
    # Load optional project wide settings
    app.config.update(common_parser.read_configuration(silent=True))
    # Load optional app specific settings
    app.config.update(app_parser.read_configuration(silent=True))

    # Setup logging
    app = init_logging(app)

    # Setup exception handling
    app = init_exception_handlers(app)

    # Register views. Import here to avoid a Flask circular dependency.
    from eduid_api.views import eduid_api_views
    app.register_blueprint(eduid_api_views)

    app.mystate = MyState(app)

    if app.mystate.yhsm:
        app.logger.info('YubiHSM: {!r}'.format(app.mystate.yhsm.version.sysinfo))
    else:
        app.logger.info('No YubiHSM attached')

    app.logger.info('Application {!r} initialized'.format(name))
    return app
