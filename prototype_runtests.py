#!/usr/bin/env python3
"""Run a CSAF 2.0 -> 2.1 converter test

SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
"""
import datetime
import json
from pathlib import Path
import re
from subprocess import run
import sys

_tests = ["input/testcase-20260310-1501-isduba-2026-001.json"]

_CONV_BINARY = "./converter_replacement.py"

def run_test(test) -> bool:
    # FIXME just one test is hardcoded

    # we only have the one for additional_properties
    completed_process = run([_CONV_BINARY, test, "tmp-out.json"],
                            capture_output=True, universal_newlines=True)

    #print(completed_process)

    if len(completed_process.stderr) > 0:
        messages = json.loads(completed_process.stderr)

    #print(messages)

    # we expect the converter to complete successfully and issue a warning
    if completed_process.returncode == 0 and "warnings" in messages:
        for w in messages["warnings"]:
            if w.find("x_test") >= 0:
                return True

    return False

def main():
    results = []
    for test in _tests:
        results.append(run_test(test))

    print(f"Run {len(results)} test(s)...")
    print("Results:", repr(results))


if __name__ == "__main__":
    main()
