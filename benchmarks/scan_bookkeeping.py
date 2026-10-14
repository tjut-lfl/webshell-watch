"""仅测文件变更判定的 CPU 开销，不代表磁盘扫描或整机吞吐量。

python benchmarks/scan_bookkeeping.py --project . --count 5000 --rounds 5
可将 --project 指向原版目录，在同一解释器下比较。中间状态写在当前目录 work/。
"""
import argparse
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time
from unittest.mock import patch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", default=".")
    parser.add_argument("--count", type=int, default=5000)
    parser.add_argument("--rounds", type=int, default=5)
    args = parser.parse_args()
    if args.count < 1 or args.rounds < 1:
        parser.error("count 和 rounds 必须大于 0")
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(Path(args.project).resolve()))
    from wsa.filescan import FileRecord, FileScanner

    scratch = Path("work")
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scratch) as tmp:
        scanner = FileScanner(lambda a: None, lambda *args: None, [], [], [".php"], tmp)
        records = {}
        for i in range(args.count):
            path = f"/benchmark/site/file-{i}.php"
            records[path] = FileRecord(path, 20, 2.0, 0o644, "root", "new")
        scanner.baseline = {p: {"size": 10, "mtime": 1.0, "digest": "old"} for p in records}
        scanner.baseline_missing = False
        samples = []
        with patch.object(scanner, "_walk", return_value=records), \
                patch.object(scanner, "scan_content", return_value=[]), \
                patch.object(scanner, "_emit"):
            for _ in range(args.rounds):
                start = time.perf_counter()
                result = scanner.scan()
                samples.append(time.perf_counter() - start)
                if len(result.modified_files) != args.count:
                    raise RuntimeError("变更文件数量不正确")
    print(json.dumps({"project": str(Path(args.project).resolve()), "files": args.count,
        "rounds": args.rounds, "median_seconds": statistics.median(samples),
        "samples_seconds": samples}, ensure_ascii=False))


if __name__ == "__main__":
    main()
