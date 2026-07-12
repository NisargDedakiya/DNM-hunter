"""Tests for the scan-lifecycle state machine (master-plan Phase 2, Priority 7).

Run: python -m unittest common.tests.test_job_lifecycle -v
"""

import unittest

from common.job_lifecycle import Job, JobState, InvalidTransition, can_transition


def _job(**kw):
    return Job(id="j1", module_name="recon", program_id="p1", **kw)


class TestTransitions(unittest.TestCase):
    def test_happy_path_queued_to_completed(self):
        j = _job()
        self.assertEqual(j.state, JobState.QUEUED)
        j.start(); self.assertEqual(j.state, JobState.RUNNING)
        j.complete()
        self.assertEqual(j.state, JobState.COMPLETED)
        self.assertEqual(j.progress, 1.0)
        self.assertTrue(j.is_terminal)

    def test_pause_resume_cycle(self):
        j = _job(); j.start()
        j.pause(); self.assertEqual(j.state, JobState.PAUSED)
        j.resume(); self.assertEqual(j.state, JobState.RUNNING)
        j.pause(); j.resume()
        self.assertEqual(j.state, JobState.RUNNING)

    def test_cancel_from_queued_and_running_and_paused(self):
        for setup in (lambda j: None, lambda j: j.start(), lambda j: (j.start(), j.pause())):
            j = _job(); setup(j)
            j.cancel()
            self.assertEqual(j.state, JobState.CANCELLED)
            self.assertTrue(j.is_terminal)

    def test_fail_then_retry_preserves_config(self):
        j = _job(config={"depth": 3}); j.start()
        j.fail("boom")
        self.assertEqual(j.state, JobState.FAILED)
        self.assertEqual(j.error, "boom")
        j.retry()
        self.assertEqual(j.state, JobState.RETRYING)
        self.assertEqual(j.retries, 1)
        self.assertIsNone(j.error)
        self.assertEqual(j.config, {"depth": 3})     # config survives retry
        j.start()                                     # RETRYING -> RUNNING
        self.assertEqual(j.state, JobState.RUNNING)

    def test_retry_budget_is_enforced(self):
        j = _job(max_retries=2); j.start()
        for _ in range(2):
            j.fail("x"); j.retry(); j.start()
        j.fail("x")
        with self.assertRaises(InvalidTransition):
            j.retry()

    def test_illegal_transitions_are_rejected(self):
        j = _job()
        with self.assertRaises(InvalidTransition):
            j.pause()                                 # can't pause a queued job
        j.start(); j.complete()
        with self.assertRaises(InvalidTransition):
            j.start()                                 # can't restart a completed job
        with self.assertRaises(InvalidTransition):
            j.cancel()                                # completed is terminal

    def test_resume_requires_paused(self):
        j = _job(); j.start()
        with self.assertRaises(InvalidTransition):
            j.resume()

    def test_can_transition_table(self):
        self.assertTrue(can_transition(JobState.RUNNING, JobState.PAUSED))
        self.assertFalse(can_transition(JobState.COMPLETED, JobState.RUNNING))
        self.assertFalse(can_transition(JobState.CANCELLED, JobState.RETRYING))


if __name__ == "__main__":
    unittest.main()
