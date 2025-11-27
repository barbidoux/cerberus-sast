"""Tests for the progress tracking module."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from cerberus.core.progress import (
    ProgressTracker,
    ScanProgress,
    create_cli_progress_callback,
    create_websocket_callback,
)


class TestScanProgress:
    """Test ScanProgress dataclass."""

    def test_create_progress(self):
        """Should create progress with defaults."""
        progress = ScanProgress(phase="context")

        assert progress.phase == "context"
        assert progress.phase_progress == 0.0
        assert progress.message is None
        assert progress.files_processed == 0

    def test_create_progress_with_values(self):
        """Should create progress with custom values."""
        progress = ScanProgress(
            phase="detection",
            phase_progress=0.5,
            message="Processing files",
            current_file="src/app.py",
            files_processed=10,
            files_total=20,
            findings_count=3,
        )

        assert progress.phase == "detection"
        assert progress.phase_progress == 0.5
        assert progress.message == "Processing files"
        assert progress.current_file == "src/app.py"
        assert progress.files_processed == 10
        assert progress.files_total == 20
        assert progress.findings_count == 3

    def test_to_dict(self):
        """Should convert to dictionary."""
        progress = ScanProgress(
            phase="inference",
            phase_progress=0.3,
            message="Classifying candidates",
        )

        data = progress.to_dict()

        assert data["phase"] == "inference"
        assert data["phase_progress"] == 0.3
        assert data["message"] == "Classifying candidates"
        assert "timestamp" in data

    def test_overall_progress_context(self):
        """Should calculate overall progress for context phase."""
        progress = ScanProgress(phase="context", phase_progress=0.5)

        # Context is 0-10%, so 50% of context = 5%
        assert progress.overall_progress == pytest.approx(0.05, rel=0.01)

    def test_overall_progress_inference(self):
        """Should calculate overall progress for inference phase."""
        progress = ScanProgress(phase="inference", phase_progress=0.5)

        # Inference is 10-30%, so 50% of inference = 20%
        assert progress.overall_progress == pytest.approx(0.2, rel=0.01)

    def test_overall_progress_detection(self):
        """Should calculate overall progress for detection phase."""
        progress = ScanProgress(phase="detection", phase_progress=0.5)

        # Detection is 30-70%, so 50% of detection = 50%
        assert progress.overall_progress == pytest.approx(0.5, rel=0.01)

    def test_overall_progress_verification(self):
        """Should calculate overall progress for verification phase."""
        progress = ScanProgress(phase="verification", phase_progress=0.5)

        # Verification is 70-100%, so 50% of verification = 85%
        assert progress.overall_progress == pytest.approx(0.85, rel=0.01)

    def test_overall_progress_complete(self):
        """Should return 100% for complete phase."""
        progress = ScanProgress(phase="complete", phase_progress=1.0)

        assert progress.overall_progress == 1.0

    def test_overall_progress_unknown_phase(self):
        """Should return 0% for unknown phase."""
        progress = ScanProgress(phase="unknown", phase_progress=0.5)

        assert progress.overall_progress == 0.0


class TestProgressTracker:
    """Test ProgressTracker class."""

    def test_create_tracker(self):
        """Should create tracker without callback."""
        tracker = ProgressTracker()

        assert tracker.current is None
        assert tracker.elapsed_seconds == 0.0

    def test_create_tracker_with_callback(self):
        """Should create tracker with callback."""
        callback = MagicMock()
        tracker = ProgressTracker(callback=callback)

        assert len(tracker._callbacks) == 1

    def test_add_callback(self):
        """Should add callback."""
        tracker = ProgressTracker()
        callback = MagicMock()

        tracker.add_callback(callback)

        assert callback in tracker._callbacks

    def test_remove_callback(self):
        """Should remove callback."""
        callback = MagicMock()
        tracker = ProgressTracker(callback=callback)

        tracker.remove_callback(callback)

        assert callback not in tracker._callbacks

    def test_start(self):
        """Should mark start time."""
        tracker = ProgressTracker()

        tracker.start()

        assert tracker._start_time is not None
        assert tracker.elapsed_seconds >= 0

    def test_update(self):
        """Should update current progress."""
        tracker = ProgressTracker()
        progress = ScanProgress(phase="context", phase_progress=0.5)

        tracker.update(progress)

        assert tracker.current == progress

    def test_update_notifies_callbacks(self):
        """Should notify callbacks on update."""
        callback = MagicMock()
        tracker = ProgressTracker(callback=callback)
        progress = ScanProgress(phase="context")

        tracker.update(progress)

        callback.assert_called_once()
        call_args = callback.call_args[0]
        assert call_args[0].phase == "context"

    def test_update_calculates_elapsed_time(self):
        """Should calculate elapsed time on update."""
        tracker = ProgressTracker()
        tracker.start()
        progress = ScanProgress(phase="context")

        tracker.update(progress)

        assert progress.elapsed_seconds >= 0

    def test_get_history(self):
        """Should return progress history."""
        tracker = ProgressTracker()
        progress1 = ScanProgress(phase="context")
        progress2 = ScanProgress(phase="inference")

        tracker.update(progress1)
        tracker.update(progress2)

        history = tracker.get_history()
        assert len(history) == 2
        assert history[0].phase == "context"
        assert history[1].phase == "inference"

    def test_callback_error_does_not_break_tracking(self):
        """Should continue tracking if callback raises exception."""

        def bad_callback(p: ScanProgress) -> None:
            raise ValueError("Callback error")

        tracker = ProgressTracker(callback=bad_callback)
        progress = ScanProgress(phase="context")

        # Should not raise
        tracker.update(progress)

        assert tracker.current == progress


class TestCLIProgressCallback:
    """Test CLI progress callback factory."""

    def test_create_callback(self):
        """Should create callback function."""
        progress_bar = MagicMock()
        task_id = MagicMock()

        callback = create_cli_progress_callback(progress_bar, task_id)

        assert callable(callback)

    def test_callback_updates_progress_bar(self):
        """Should update progress bar on callback."""
        progress_bar = MagicMock()
        task_id = "task-1"
        callback = create_cli_progress_callback(progress_bar, task_id)
        progress = ScanProgress(phase="detection", phase_progress=0.5, message="Processing")

        callback(progress)

        progress_bar.update.assert_called_once()
        call_kwargs = progress_bar.update.call_args[1]
        assert "description" in call_kwargs
        assert "completed" in call_kwargs

    def test_callback_includes_message_in_description(self):
        """Should include message in description."""
        progress_bar = MagicMock()
        task_id = "task-1"
        callback = create_cli_progress_callback(progress_bar, task_id)
        progress = ScanProgress(phase="detection", message="Analyzing flows")

        callback(progress)

        call_kwargs = progress_bar.update.call_args[1]
        assert "Analyzing flows" in call_kwargs["description"]

    def test_callback_includes_file_in_description(self):
        """Should include current file in description when no message."""
        progress_bar = MagicMock()
        task_id = "task-1"
        callback = create_cli_progress_callback(progress_bar, task_id)
        progress = ScanProgress(phase="context", current_file="src/main.py")

        callback(progress)

        call_kwargs = progress_bar.update.call_args[1]
        assert "src/main.py" in call_kwargs["description"]


class TestWebSocketCallback:
    """Test WebSocket progress callback factory."""

    def test_create_callback(self):
        """Should create callback function."""
        send_func = MagicMock()

        callback = create_websocket_callback(send_func)

        assert callable(callback)

    def test_callback_sends_progress_dict(self):
        """Should send progress as dict via send function."""
        send_func = MagicMock()
        callback = create_websocket_callback(send_func)
        progress = ScanProgress(phase="verification", phase_progress=0.8)

        callback(progress)

        send_func.assert_called_once()
        sent_data = send_func.call_args[0][0]
        assert sent_data["type"] == "progress"
        assert "data" in sent_data
        assert sent_data["data"]["phase"] == "verification"
