"""Background maintenance loop: lease expiry, sign-in failure pruning and scheduled scan enqueueing."""
import logging
import threading

from .service import enqueue_due, prune_login_failures, requeue_expired

log = logging.getLogger("crab_risk_scan.server")


class Scheduler:
    """Runs `tick` every `interval` seconds on a daemon thread until stopped."""

    def __init__(self, sessions, settings):
        self.sessions = sessions
        self.settings = settings
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="crab-scheduler", daemon=True)

    def tick(self):
        with self.sessions() as db:
            requeued, failed = requeue_expired(db)
            pruned = prune_login_failures(db, self.settings)
            db.commit()
            if requeued or failed:
                log.info("lease expiry: %d jobs requeued, %d failed", requeued, failed)
            if pruned:
                log.info("pruned %d expired sign-in failure records", pruned)
        with self.sessions() as db:
            created = enqueue_due(db, self.settings)
            if created:
                log.info("scheduler enqueued %d jobs", len(created))
        return created

    def _run(self):
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - keep the loop alive across transient database errors
                log.exception("scheduler tick failed")
            self._stop.wait(self.settings.scheduler_interval)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=10)
