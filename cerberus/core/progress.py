"""
Progress Tracking for Scan Operations.

Provides real-time progress updates for the 4-phase pipeline,
supporting both CLI progress bars and WebSocket streaming.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional


@dataclass
class ScanProgress:
    """
    Progress update for a scan operation.

    Represents the current state of a scan, suitable for
    display in CLI progress bars or WebSocket streaming.
    """

    phase: str  # "context", "inference", "detection", "verification", "complete"
    phase_progress: float = 0.0  # 0.0 to 1.0

    # Optional details
    message: Optional[str] = None
    current_file: Optional[str] = None
    files_processed: int = 0
    files_total: int = 0
    findings_count: int = 0

    # Timing
    elapsed_seconds: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "phase": self.phase,
            "phase_progress": self.phase_progress,
            "message": self.message,
            "current_file": self.current_file,
            "files_processed": self.files_processed,
            "files_total": self.files_total,
            "findings_count": self.findings_count,
            "elapsed_seconds": self.elapsed_seconds,
            "timestamp": self.timestamp.isoformat(),
        }

    @property
    def overall_progress(self) -> float:
        """
        Calculate overall progress across all phases.

        Phases are weighted:
        - Context: 10%
        - Inference: 20%
        - Detection: 40%
        - Verification: 30%
        """
        phase_weights = {
            "context": (0.0, 0.1),
            "inference": (0.1, 0.3),
            "detection": (0.3, 0.7),
            "verification": (0.7, 1.0),
            "complete": (1.0, 1.0),
        }

        if self.phase not in phase_weights:
            return 0.0

        start, end = phase_weights[self.phase]
        phase_range = end - start
        return start + (self.phase_progress * phase_range)


class ProgressTracker:
    """
    Tracks and reports scan progress.

    Supports multiple callbacks for different output targets
    (CLI progress bar, WebSocket, logging, etc.).
    """

    def __init__(
        self,
        callback: Optional[Callable[[ScanProgress], None]] = None,
    ) -> None:
        """
        Initialize progress tracker.

        Args:
            callback: Optional callback function for progress updates.
        """
        self._callbacks: list[Callable[[ScanProgress], None]] = []
        if callback:
            self._callbacks.append(callback)

        self._start_time: Optional[float] = None
        self._current_progress: Optional[ScanProgress] = None
        self._history: list[ScanProgress] = []

    def add_callback(self, callback: Callable[[ScanProgress], None]) -> None:
        """Add a callback for progress updates."""
        self._callbacks.append(callback)

    def remove_callback(self, callback: Callable[[ScanProgress], None]) -> None:
        """Remove a callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def start(self) -> None:
        """Mark the start of tracking."""
        self._start_time = time.time()
        self._history = []

    def update(self, progress: ScanProgress) -> None:
        """
        Update current progress and notify callbacks.

        Args:
            progress: Current progress state.
        """
        # Calculate elapsed time
        if self._start_time is not None:
            progress.elapsed_seconds = time.time() - self._start_time

        self._current_progress = progress
        self._history.append(progress)

        # Notify all callbacks
        for callback in self._callbacks:
            try:
                callback(progress)
            except Exception:
                # Don't let callback errors break the scan
                pass

    @property
    def current(self) -> Optional[ScanProgress]:
        """Get current progress state."""
        return self._current_progress

    @property
    def elapsed_seconds(self) -> float:
        """Get elapsed time since start."""
        if self._start_time is None:
            return 0.0
        return time.time() - self._start_time

    def get_history(self) -> list[ScanProgress]:
        """Get progress history."""
        return self._history.copy()


def create_cli_progress_callback(
    progress_bar: Any,
    task_id: Any,
) -> Callable[[ScanProgress], None]:
    """
    Create a callback for Rich progress bar updates.

    Args:
        progress_bar: Rich Progress instance.
        task_id: Task ID from progress.add_task().

    Returns:
        Callback function for ProgressTracker.
    """

    def callback(p: ScanProgress) -> None:
        description = f"[{p.phase}]"
        if p.message:
            description = f"{description} {p.message}"
        elif p.current_file:
            description = f"{description} {p.current_file}"

        progress_bar.update(
            task_id,
            description=description,
            completed=p.overall_progress * 100,
        )

    return callback


def create_websocket_callback(
    send_func: Callable[[dict[str, Any]], None],
) -> Callable[[ScanProgress], None]:
    """
    Create a callback for WebSocket progress streaming.

    Args:
        send_func: Async function to send dict via WebSocket.

    Returns:
        Callback function for ProgressTracker.
    """

    def callback(p: ScanProgress) -> None:
        send_func({
            "type": "progress",
            "data": p.to_dict(),
        })

    return callback
