"""Backend -> UI event contract (no Textual import).

These dataclasses are the one-way messages the pipeline/runner emit to the UI.
The UI installs an `emit(Event)` callable; in a worker thread it is invoked via
Textual's `call_from_thread`. Backend never imports the UI.
"""

from dataclasses import dataclass, field
from typing import Dict


@dataclass(frozen=True)
class StageStarted:
    target: str
    stage: str
    command: str


@dataclass(frozen=True)
class OutputLine:
    target: str
    stage: str
    line: str


@dataclass(frozen=True)
class StageProgress:
    target: str
    stage: str
    lines: int
    elapsed_sec: float


@dataclass(frozen=True)
class StageFinished:
    target: str
    stage: str
    status: str                       # done|partial|cancelled|error|skipped
    outputs: Dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class QueueProgress:
    index: int
    total: int
    target: str


@dataclass(frozen=True)
class Notice:
    level: str                        # info|ok|warn|error
    text: str


__all__ = [
    "StageStarted", "OutputLine", "StageProgress", "StageFinished",
    "QueueProgress", "Notice",
]
