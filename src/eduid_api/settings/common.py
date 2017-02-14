DEBUG = True

# Database URIs
MONGO_URI = 'mongodb://localhost'

# Application specific settings
ADD_RAW_ALLOW = ''      # comma-separated list of IP addresses
KEYSTORE_FN = ''        # keystore filename
JOSE_ALG = 'RS256'      # JOSE signing algorithm
VCCS_BASE_URL = 'http://vccsclient:8550/'
OATH_AEAD_KEYHANDLE = None
OATH_YHSM_DEVICE = ''
OATH_AEAD_GEN_URL = ''  # URL to another instance of eduid-api with a YubiHSM

# Celery config
CELERY_CONFIG = {
    'BROKER_URL': 'amqp://',
    'CELERY_RESULT_BACKEND': 'amqp',
    'CELERY_TASK_SERIALIZER': 'json'
}

# Logging
LOG_FILE = None
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_LEVEL = 'DEBUG'
LOG_MAX_BYTES = 1000000  # 1 MB
LOG_BACKUP_COUNT = 10
