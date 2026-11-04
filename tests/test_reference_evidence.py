"""Evidence subprocesses finish before their parent deletes native store files."""

import subprocess
import tempfile

import pytest

from scripts import reference_evidence


def test_application_is_closed_when_the_evidence_journey_fails(tmp_path, monkeypatch):
    closed = []

    class FailingApplication:
        def __init__(self, root):
            assert root == tmp_path

        def document(self, *_args):
            raise RuntimeError("simulated application failure")

        def close(self):
            closed.append(True)

    monkeypatch.setattr(reference_evidence, "MemoryApplication", FailingApplication)
    with pytest.raises(RuntimeError, match="simulated application failure"):
        reference_evidence._run_in_workspace(tmp_path)
    assert closed == [True]


def test_failed_worker_does_not_produce_successful_evidence_or_leave_a_workspace(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    def failed_worker(*_args, **_kwargs):
        raise subprocess.CalledProcessError(1, "evidence-worker")

    monkeypatch.setattr(reference_evidence.subprocess, "run", failed_worker)
    with pytest.raises(subprocess.CalledProcessError):
        reference_evidence.run()
    assert list(tmp_path.iterdir()) == []


def test_real_chroma_evidence_exits_before_temporary_workspace_cleanup(tmp_path, monkeypatch):
    pytest.importorskip("chromadb")
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    result = reference_evidence.run()
    assert result["clean_verification_status"] == "VERIFIED_WITHIN_SCOPE"
    assert result["failed_actions"] == 0
    assert result["public_context_retained"]
    assert result["bypasses_detected"] >= 2
    assert result["bypass_verification_status"] == "PARTIAL"
    assert list(tmp_path.iterdir()) == []
