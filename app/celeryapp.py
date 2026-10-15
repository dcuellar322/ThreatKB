import os
from celery import Celery, Task
from app import app


def make_celery(flask_app):
    class FlaskTask(Task):
        def __call__(self, *args, **kwargs):
            with flask_app.app_context():
                return self.run(*args, **kwargs)

    broker = os.getenv("REDIS_BROKER_URL") or flask_app.config.get("REDIS_BROKER_URL") or flask_app.config.get("BROKER_URL") or "redis://127.0.0.1:6379/0"
    celery_app = Celery(flask_app.import_name, task_cls=FlaskTask, broker=broker, backend=broker)
    celery_app.conf.update(task_serializer="json", result_serializer="json", accept_content=["json"],
                           timezone="UTC", broker_connection_retry_on_startup=True,
                           beat_schedule={"scheduled-confidence": {
                               "task": "threatkb.apply_scheduled_confidence", "schedule": 60.0},
                               "content-promotion": {"task": "threatkb.promote_ready_content", "schedule": 60.0}})
    return celery_app


celery = make_celery(app)
