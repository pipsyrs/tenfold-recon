"""Multi-target queue. Sequential iteration; one output folder per target.

The caller sets cfg["target"] = target then uses pipeline.target_dir(cfg) so the
existing output_base/<target>/ layout is reused. UI emits QueueProgress itself.
"""

from pathlib import Path


def parse_targets(text):
    """Parse manual input: split on newlines/commas/whitespace, drop #comments, dedupe."""
    out, seen = [], set()
    for chunk in (text or "").replace(",", "\n").splitlines():
        t = chunk.strip()
        if not t or t.startswith("#"):
            continue
        t = t.replace("https://", "").replace("http://", "")
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


class TargetQueue:
    def __init__(self, targets):
        if isinstance(targets, str):
            targets = parse_targets(targets)
        # normalize + dedupe preserve order (same rules as parse_targets)
        seen, clean = set(), []
        for t in targets:
            t = (t or "").strip()
            if not t or t.startswith("#"):
                continue
            t = t.replace("https://", "").replace("http://", "")
            if t not in seen:
                seen.add(t)
                clean.append(t)
        self.targets = clean
        self.total = len(clean)

    @classmethod
    def from_file(cls, path):
        text = Path(path).read_text(errors="ignore")
        return cls(parse_targets(text))

    def __len__(self):
        return self.total

    def __iter__(self):
        """Yield (index, total, target); index is 1-based."""
        for i, t in enumerate(self.targets, start=1):
            yield i, self.total, t
