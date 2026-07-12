"""Tests for the job queue / admission logic (master-plan Phase 2, Priority 7).

Run: python -m unittest common.tests.test_job_manager -v
"""

import unittest

from common.job_lifecycle import Job, JobState
from common.job_manager import JobManager


def _job(i):
    return Job(id=f"j{i}", module_name="recon", program_id="p1")


class TestJobManager(unittest.TestCase):
    def test_concurrency_cap_limits_startable(self):
        m = JobManager(max_concurrent=2)
        for i in range(4):
            m.submit(_job(i))
        startable = m.next_startable()
        self.assertEqual(len(startable), 2)             # only 2 slots

    def test_running_jobs_consume_slots(self):
        m = JobManager(max_concurrent=2)
        jobs = [m.submit(_job(i)) for i in range(3)]
        jobs[0].start()                                  # one running
        self.assertEqual(m.running_count, 1)
        self.assertEqual(len(m.next_startable()), 1)     # only 1 slot left

    def test_admit_predicate_gates_start(self):
        m = JobManager(max_concurrent=5)
        for i in range(3):
            m.submit(_job(i))
        # governor refuses everything -> nothing startable despite free slots
        self.assertEqual(m.next_startable(admit=lambda j: False), [])
        # governor allows only j1
        allowed = m.next_startable(admit=lambda j: j.id == "j1")
        self.assertEqual([j.id for j in allowed], ["j1"])

    def test_queue_position(self):
        m = JobManager(max_concurrent=1)
        for i in range(3):
            m.submit(_job(i))
        self.assertEqual(m.position_of("j0"), 1)
        self.assertEqual(m.position_of("j2"), 3)
        m.get("j0").start()
        self.assertIsNone(m.position_of("j0"))           # running, not queued

    def test_retrying_jobs_are_startable(self):
        m = JobManager(max_concurrent=2)
        j = m.submit(_job(0))
        j.start(); j.fail("x"); j.retry()
        self.assertEqual(j.state, JobState.RETRYING)
        self.assertIn(j, m.next_startable())

    def test_prune_terminal_removes_finished(self):
        m = JobManager(max_concurrent=2)
        a, b = m.submit(_job(0)), m.submit(_job(1))
        a.start(); a.complete()
        b.start(); b.cancel()
        self.assertEqual(m.prune_terminal(), 2)
        self.assertEqual(m.all(), [])

    def test_duplicate_submit_rejected(self):
        m = JobManager()
        m.submit(_job(0))
        with self.assertRaises(ValueError):
            m.submit(_job(0))


if __name__ == "__main__":
    unittest.main()
