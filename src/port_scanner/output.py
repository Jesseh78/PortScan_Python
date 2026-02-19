from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from .scanner import ScanResult


def save_csv(results: Iterable[ScanResult], path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    with p.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["host", "port", "is_open", "banner", "error"])
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))


def save_json(results: Iterable[ScanResult], path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    payload = [asdict(r) for r in results]
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
