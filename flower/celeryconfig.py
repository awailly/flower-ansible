## Broker settings.
BROKER_URL = 'amqp://guest:guest@localhost:5672//'

# List of modules to import when celery starts.
CELERY_IMPORTS = ('hardening.tasks', )

## Using the database to store task state and results.
CELERY_RESULT_BACKEND = 'redis://'

#CELERY_ANNOTATIONS = {'tasks.add': {'rate_limit': '10/s'}}
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_ACCEPT_CONTENT=['json']
CELERY_TIMEZONE = 'Europe/Paris'
CELERY_ENABLE_UTC = True
