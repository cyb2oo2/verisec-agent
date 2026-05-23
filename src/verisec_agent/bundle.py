from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from verisec_agent.models import ReviewReport


class BundleWriter:
    def __init__(self, bundle_dir: Path) -> None:
        self.bundle_dir = bundle_dir

    def prepare(self) -> None:
        self.bundle_dir.mkdir(parents=True, exist_ok=True)
        (self.bundle_dir / "inputs").mkdir(exist_ok=True)
        (self.bundle_dir / "tools").mkdir(exist_ok=True)

    def copy_diff(self, diff_path: Path) -> Path:
        target = self.bundle_dir / "inputs" / "diff.patch"
        shutil.copyfile(diff_path, target)
        return target

    def write_report(self, report: ReviewReport) -> Path:
        target = self.bundle_dir / "report.json"
        report.write_json(target)
        return target

    def write_source_metadata(self, source: dict[str, Any]) -> Path:
        target = self.bundle_dir / "inputs" / "source.json"
        target.write_text(json.dumps(source, indent=2, sort_keys=True), encoding="utf-8")
        return target
