from setuptools import setup, find_packages
import os


here = os.path.abspath(os.path.dirname(__file__))
README = 'eduID API application'
CHANGES = ''
try:
    README = open(os.path.join(here, 'README.rst')).read()
except IOError:
    pass
try:
    CHANGES = open(os.path.join(here, 'CHANGES.rst')).read()
except IOError:
    pass

version = '0.2.5'

requires = [
    'eduid_am >= 0.4.9',
    'pymongo >= 3.6',
    'cherrypy >= 3.6.0',
    'simplejson >= 3.6.5',
    'jose >= 0.3.0',
    'vccs_client >= 0.4.2',
    'qrcode >= 5.1',
    'requests >= 2.5.1',
    'pyhsm > 1.0.2'
]


test_requires = [
]

testing_extras = test_requires + [
    'nose==1.2.1',
    'coverage==3.6',
    'nosexcover>=1.0.8',
]


setup(
    name='eduid_api',
    version=version,
    description='eduID API application',
    long_description=README + '\n\n' + CHANGES,
    # TODO: add classifiers
    classifiers=[
        # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    ],
    keywords='identity federation saml',
    author='NORDUnet A/S',
    url='https://github.com/SUNET/eduid-api',
    license='BSD',
    packages=['eduid_api',],
    package_dir = {'': 'src'},
    include_package_data=True,
    zip_safe=False,
    install_requires=requires,
    tests_require=test_requires,
    extras_require={
        'testing': testing_extras,
    },
    test_suite='eduid_api',
    entry_points={
        'console_scripts': ['eduid_api=eduid_api.eduid_apibackend:main',
                            ]
        },
)
