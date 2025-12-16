import os
from celery import Celery
from celery.schedules import crontab
from django.apps import apps
import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="pycparser")

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'payd.settings')

app = Celery('payd')

app.config_from_object('django.conf:settings', namespace='CELERY')

app.autodiscover_tasks(lambda: [n.name for n in apps.get_app_configs()])

@app.task(bind=True, ignore_result=True)
def debug_task(self):
    print(f'Request: {self.request!r}')

app.conf.beat_schedule = {
    "verify-pending-paystack-transactions-hourly": {
        "task": "api.tasks.verify_pending_paystack_transactions",
        "schedule": crontab(minute=0), # Run every hour at minute 0
    },
    "revoke-expired-api-keys-daily": {
        "task": "api.tasks.revoke_expired_api_keys",
        "schedule": crontab(minute="*/45"), # Run every 45 minutes
    },
}
