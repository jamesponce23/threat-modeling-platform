"""RQ queue handle.

The scan job is enqueued by dotted path as a string, so B1 does not need to
import `app.worker` — which does not exist until B4. The job sits in Redis
until a worker is running.
"""

from __future__ import annotations

from redis import Redis
from rq import Queue

from app.config import settings

redis_conn = Redis.from_url(settings.redis_url)
scan_queue = Queue("scans", connection=redis_conn)


def enqueue_scan(submission_id: int) -> str:
    job = scan_queue.enqueue("app.worker.run_scan", submission_id, job_timeout=settings.scan_timeout_sec)
    return job.id
