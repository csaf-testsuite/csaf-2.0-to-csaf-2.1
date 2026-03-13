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
import tempfile

_tests = ["input/testcase-1-20260311-1512-isduba-2026-001.json",
          "input/testcase-2-20260312-1651-isduba-2025-01.json",
          "input/testcase-3-20260313-1429-isduba-2026-001.json",
          ]

_CONV_BINARY = "./converter_replacement.py"

def check_testcase1(csaf_doc, returncode, messages) -> bool:
    d = csaf_doc["document"]

    additional_property_name = "x_test_q7VQf"
    if additional_property_name in d:
        return False

    # we expect the converter to complete successfully and issue a warning
    # from https://github.com/oasis-tcs/csaf/blob/master/csaf_2.1/prose/share/csaf-v2.1-draft.md#conformance-clause-18-csaf-2-0-to-csaf-2-1-converter
    # 9.1.18  Conformance Clause 18: CSAF 2.0 to CSAF 2.1 Converter
    # toplevel requirement
    if returncode == 0 and "warnings" in messages:
        for w in messages["warnings"]:
            if w.find("additional property") >= 0 and w.find("not converted") >=0:
                return True

    return False


def check_testcase2(csaf_doc, returncode, messages) -> bool:
    rh = csaf_doc["document"]["tracking"]["revision_history"]

    if returncode > 0:
        return False

    for rev in rh:
        if rev["date"].endswith(":60Z"):
            return False

    if not rh[0]["date"].endswith(":59.999999Z"):
        return False

    if "warnings" in messages:
        for w in messages["warnings"]:
            if w.find("valid leap second") and w.find("prohibited") \
                    and w.find("replaced"):
                return True

    return False


def find_descendants(csaf_object, key) -> list:
    """Search dicts and lists based object tree like from json.load() for key.

    Return list of values.

    Works recursively

    >>> o = { "c": "l", "b": [{"c":2,"d":3},{"e":4,"c":5}]}
    >>> find_descendants(o, "c")
    ['l', 2, 5]
    """
    found = []
    if type(csaf_object) == dict:
        if key in csaf_object:
            found.append(csaf_object[key])
        for v in csaf_object.values():
            if type(v) in [dict,list]:
                found.extend(find_descendants(v, key))
    elif type(csaf_object) == list:
        for v in csaf_object:
            if type(v) in [dict,list]:
                found.extend(find_descendants(v, key))
    return found


def check_testcase3(csaf_doc, returncode, messages) -> bool:
    if returncode > 0:
        return False

    p = csaf_doc["product_tree"]
    category_values = find_descendants(p, "category")

    if "legacy" in category_values:
        return False

    #TODO check if changed to category is product_name

    if "warnings" in messages:
        for w in messages["warnings"]:
            if w.find("replaced") and w.find("legacy") \
                    and w.find("product_name"):
                return True


def run_test(test, resultdir_name) -> bool:
    output_filename = resultdir_name + "/tmp-out.json"
    completed_process = run([_CONV_BINARY, test, output_filename],
                            capture_output=True, universal_newlines=True)

    print(completed_process)

    if len(completed_process.stderr) > 0:
        messages = json.loads(completed_process.stderr)

    print(messages)

    with open(output_filename, "rt", encoding="utf-8") as file:
        output_csaf_doc = json.load(file)

    if "testcase-1" in test:
         return check_testcase1(output_csaf_doc, completed_process.returncode,
                                messages)
    if "testcase-2" in test:
         return check_testcase2(output_csaf_doc, completed_process.returncode,
                                messages)
    if "testcase-3" in test:
         return check_testcase3(output_csaf_doc, completed_process.returncode,
                                messages)

    return False


def main():
    results = []

    # using a result directory that is automatically removed
    with tempfile.TemporaryDirectory() as resultdir_name:
        for test in _tests:
            results.append(run_test(test, resultdir_name))

    print(f"Run {len(results)} test(s)...")
    print("Results:", repr(results))


if __name__ == "__main__":
    main()
