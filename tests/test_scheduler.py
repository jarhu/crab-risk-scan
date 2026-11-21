import os
import tempfile
import threading
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from crab_risk_scan.server.cron import CronExpression, next_run


class CronTests(unittest.TestCase):
    def test_fields(self):
        cron = CronExpression("*/15 9-17 * * mon-fri")
        self.assertEqual(sorted(cron.minutes), [0, 15, 30, 45])
        self.assertEqual(sorted(cron.hours), list(range(9, 18)))
        self.assertEqual(sorted(cron.weekdays), [1, 2, 3, 4, 5])
        self.assertEqual(sorted(CronExpression("5,10-12,50/5 * * * *").minutes), [5, 10, 11, 12, 50, 55])
        self.assertEqual(sorted(CronExpression("0 0 1 JAN,jul-sep/2 *").months), [1, 7, 9])
        self.assertEqual(sorted(CronExpression("0 0 * * 7").weekdays), [0])
        self.assertEqual(sorted(CronExpression("0 0 * * 5-7").weekdays), [0, 5, 6])
        self.assertEqual(str(CronExpression("  0   3 * *   *  ")), "0 3 * * *")

    def test_invalid_expressions(self):
        for text in ("", "* * * *", "* * * * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *",
                     "* * * * 8", "*/0 * * * *", "5-1 * * * *", "a * * * *", "1,,2 * * * *", "* * * foo *",
                     "0 0 30 2 *", "0 0 31 4,6,9,11 *", "-1 * * * *", "1-2-3 * * * *"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                CronExpression(text)
        with self.assertRaises(ValueError):
            CronExpression(None)

    def test_next_after(self):
        moment = datetime(2026, 11, 20, 10, 7, 30)
        self.assertEqual(next_run("*/15 * * * *", moment), datetime(2026, 11, 20, 10, 15))
        self.assertEqual(next_run("0 3 * * *", moment), datetime(2026, 11, 21, 3, 0))
        self.assertEqual(next_run("0 0 1 1 *", moment), datetime(2027, 1, 1, 0, 0))
        self.assertEqual(next_run("30 2 * * sun", moment), datetime(2026, 11, 22, 2, 30))
        self.assertEqual(next_run("0 12 29 2 *", moment), datetime(2028, 2, 29, 12, 0))
        self.assertEqual(next_run("* * * * *", datetime(2026, 12, 31, 23, 59)), datetime(2027, 1, 1, 0, 0))
        exact = datetime(2026, 11, 20, 10, 15)
        self.assertEqual(next_run("*/15 * * * *", exact), datetime(2026, 11, 20, 10, 30))
        aware = datetime(2026, 11, 20, 10, 7, tzinfo=UTC)
        self.assertEqual(next_run("0 * * * *", aware).tzinfo, UTC)

    def test_day_of_month_or_day_of_week(self):
        cron = CronExpression("0 0 12 * fri")  # either the 12th or any Friday, as in Vixie cron
        self.assertEqual(cron.next_after(datetime(2026, 11, 1)), datetime(2026, 11, 6))
        self.assertEqual(cron.next_after(datetime(2026, 11, 7)), datetime(2026, 11, 12))
        both = CronExpression("0 0 */10 * *")
        self.assertEqual(both.next_after(datetime(2026, 11, 2)), datetime(2026, 11, 11))
        starred = CronExpression("0 0 * * */2")  # star-prefixed day of week keeps AND semantics
        self.assertEqual(starred.next_after(datetime(2026, 11, 20)), datetime(2026, 11, 21))
        self.assertTrue(cron.matches(datetime(2026, 11, 12)))
        self.assertFalse(cron.matches(datetime(2026, 11, 11)))


try:
    from sqlalchemy import select, update

    from crab_risk_scan.server.config import Settings
    from crab_risk_scan.server.db import Job, LoginFailure, Project, Schedule, initialize, make_engine, utcnow
    from crab_risk_scan.server.scheduler import Scheduler
    from crab_risk_scan.server.service import enqueue_due, prune_login_failures
    SERVER = True
except ImportError:  # the server extra is optional
    SERVER = False


@unittest.skipUnless(SERVER, "server extra not installed")
class EnqueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        base = Path(self.temp.name)
        root = base / "repos"
        (root / "demo").mkdir(parents=True)
        self.path = str(root / "demo")
        self.url = f"sqlite:///{(base / 'crab.db').as_posix()}"
        self.settings = Settings(database_url=self.url, data_dir=base, scan_roots=(root,),
                                 scheduler=False)
        self.engines = [make_engine(self.url) for _ in range(4)]
        self.instances = [initialize(engine) for engine in self.engines]
        with self.instances[0]() as db:
            project = Project(key="demo", name="Demo")
            db.add(project)
            db.flush()
            self.schedule = Schedule(project_id=project.id, cron="*/5 * * * *",
                                     source={"type": "path", "path": self.path}, options={"engines": "none"},
                                     admin_source=True, enabled=True, next_run_at=utcnow() - timedelta(minutes=1))
            db.add(self.schedule)
            db.commit()

    def tearDown(self):
        for engine in self.engines:
            engine.dispose()
        self.temp.cleanup()

    def jobs(self):
        with self.instances[0]() as db:
            return db.scalars(select(Job)).all()

    def test_due_schedule_enqueues_once_across_instances(self):
        barrier = threading.Barrier(len(self.instances))
        results, errors = [], []

        def run(sessions):
            try:
                with sessions() as db:
                    barrier.wait()
                    results.append(enqueue_due(db, self.settings))
            except Exception as exc:  # surfaced through the assertion below
                errors.append(exc)

        threads = [threading.Thread(target=run, args=(sessions,)) for sessions in self.instances]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual(errors, [])
        self.assertEqual(sorted(len(created) for created in results), [0, 0, 0, 1])
        jobs = self.jobs()
        self.assertEqual(len(jobs), 1)
        self.assertEqual((jobs[0].status, jobs[0].schedule_id, jobs[0].options), ("queued", self.schedule.id,
                                                                                 {"engines": "none"}))
        with self.instances[0]() as db:
            schedule = db.get(Schedule, self.schedule.id)
            self.assertGreater(schedule.next_run_at, utcnow())
            self.assertEqual(schedule.next_run_at.minute % 5, 0)
            self.assertEqual(schedule.last_job_id, jobs[0].id)
            self.assertIsNotNone(schedule.last_run_at)
        with self.instances[1]() as db:
            self.assertEqual(enqueue_due(db, self.settings), [])

    def test_stale_compare_and_set_loses(self):
        with self.instances[0]() as db:
            # Another instance already advanced next_run_at after this one read it.
            db.execute(update(Schedule).values(next_run_at=utcnow() + timedelta(hours=1)))
            db.commit()
            self.assertEqual(len(enqueue_due(db, self.settings, now=utcnow() + timedelta(hours=2))), 1)
        with self.instances[1]() as db:
            self.assertEqual(enqueue_due(db, self.settings, now=utcnow() + timedelta(hours=2)), [])

    def test_disabled_and_rejected_sources(self):
        with self.instances[0]() as db:
            db.execute(update(Schedule).values(enabled=False))
            db.commit()
            self.assertEqual(enqueue_due(db, self.settings), [])
            db.execute(update(Schedule).values(enabled=True))
            db.commit()
        narrowed = Settings(database_url=self.url, data_dir=self.settings.data_dir, scan_roots=(), scheduler=False)
        with self.instances[0]() as db:
            created = enqueue_due(db, narrowed)
        self.assertEqual(len(created), 1)
        job = self.jobs()[0]
        self.assertEqual(job.status, "failed")
        self.assertIn("schedule source rejected", job.error)

    def test_scheduler_tick_requeues_expired_leases_and_enqueues(self):
        scheduler = Scheduler(self.instances[0], self.settings)
        self.assertEqual(len(scheduler.tick()), 1)
        with self.instances[0]() as db:
            db.execute(update(Job).values(status="running", attempts=1,
                                          lease_expires_at=utcnow() - timedelta(seconds=5)))
            db.commit()
        self.assertEqual(scheduler.tick(), [])
        self.assertEqual(self.jobs()[0].status, "queued")

    def test_member_schedules_need_the_project_scan_path_at_run_time(self):
        with self.instances[0]() as db:
            db.execute(update(Schedule).values(admin_source=False))
            db.commit()
            enqueue_due(db, self.settings)
        job = self.jobs()[0]
        self.assertEqual(job.status, "failed")
        self.assertIn("scan_path", job.error)
        with self.instances[0]() as db:
            db.execute(update(Project).values(scan_path=self.path))
            db.execute(update(Schedule).values(next_run_at=utcnow() - timedelta(minutes=1)))
            db.commit()
            enqueue_due(db, self.settings)
        self.assertEqual(sorted(job.status for job in self.jobs()), ["failed", "queued"])

    def test_git_schedules_follow_the_current_host_policy(self):
        with self.instances[0]() as db:
            db.execute(update(Schedule).values(source={"type": "git", "url": "https://git.example.com/r.git"}))
            db.commit()
            enqueue_due(db, self.settings)
        job = self.jobs()[0]
        self.assertEqual(job.status, "failed")
        self.assertIn("CRAB_GIT_HOSTS", job.error)

    def test_scheduler_tick_prunes_expired_login_failures(self):
        now = utcnow()
        window = timedelta(seconds=self.settings.login_lockout_seconds)
        with self.instances[0]() as db:
            db.add_all([
                LoginFailure(kind="user", key="stale", failures=2, first_failure_at=now - window * 2),
                LoginFailure(kind="client", key="10.0.0.1", failures=9, first_failure_at=now - window * 2,
                             locked_until=now - timedelta(seconds=1)),
                LoginFailure(kind="user", key="locked", failures=5, first_failure_at=now - window * 2,
                             locked_until=now + timedelta(minutes=5)),
                LoginFailure(kind="user", key="recent", failures=1, first_failure_at=now),
            ])
            db.commit()
        Scheduler(self.instances[0], self.settings).tick()
        with self.instances[0]() as db:
            self.assertEqual(sorted(row.key for row in db.scalars(select(LoginFailure))), ["locked", "recent"])
            self.assertEqual(prune_login_failures(db, self.settings), 0)

    def test_background_thread_starts_and_stops(self):
        scheduler = Scheduler(self.instances[0], Settings(database_url=self.url, data_dir=self.settings.data_dir,
                                                          scan_roots=self.settings.scan_roots,
                                                          scheduler_interval=0.1))
        scheduler.start()
        try:
            for _ in range(100):
                if self.jobs():
                    break
                threading.Event().wait(0.05)
        finally:
            scheduler.stop()
        self.assertEqual(len(self.jobs()), 1)
        self.assertFalse(scheduler._thread.is_alive())


if __name__ == "__main__":
    unittest.main()
