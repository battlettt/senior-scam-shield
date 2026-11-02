"""Run every test without pytest: python -m tests"""

import importlib
import inspect
import sys
import traceback
from pathlib import Path


def collect():
    for path in sorted(Path(__file__).parent.glob("test_*.py")):
        module = importlib.import_module(f"tests.{path.stem}")
        tests = [(name, fn) for name, fn in vars(module).items()
                 if name.startswith("test_") and inspect.isfunction(fn)]
        tests.sort(key=lambda pair: pair[1].__code__.co_firstlineno)
        for name, fn in tests:
            yield f"{path.stem}::{name}", fn


def main():
    passed, failures = 0, []
    for label, fn in collect():
        try:
            fn()
            passed += 1
        except Exception:  # report every failure, keep going
            failures.append((label, traceback.format_exc()))
    for label, trace in failures:
        print(f"FAIL {label}\n{trace}")
    print(f"{passed} passed, {len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
