#!/usr/bin/env python3
"""Run a CSAF 2.0 -> 2.1 converter test

SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
"""
import datetime
from enum import Enum
import json
import jsonpath_rfc9535
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
            if w.find("additional property") >= 0 and \
                    w.find("not converted") >=0:
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
            if w.find("valid leap second") >=0 and w.find("prohibited") >=0 \
                    and w.find("replaced") >=0:
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

    #check if changed to category is product_name
    found_transformed = False
    for b in p["branches"]:
        if b["name"] == "the attic for OurProduct" \
                and b["category"] == "product_name":
            found_transformed = True

    if found_transformed and "warnings" in messages:
        for w in messages["warnings"]:
            if w.find("replaced") >=0  and w.find("legacy") >=0 \
                    and w.find("product_name") >=0:
                return True

    return False


def check_all_substrs_in(substrs: list, msgs: list) -> bool:
    """Check if all substrings are in one of the messages.

    >>> check_all_substrs_in(["b"],["abc"])
    True
    >>> check_all_substrs_in(["f","d"],["abc","def"])
    True
    >>> check_all_substrs_in(["a","d"],["abc","def"])
    False

    Both lists must have at least one entry.

    >>> check_all_substrs_in(None, ["abc"])
    False
    >>> check_all_substrs_in([],["abc"])
    False
    >>> check_all_substrs_in(["a"],[])
    False
    >>> check_all_substrs_in(["a"],None)
    False
    """
    if not substrs or not msgs:
        return False

    for msg in msgs:
        missed_a_substring = False
        for substr in substrs:
            if substr not in msg:
                missed_a_substring = True
        if not missed_a_substring:
            return True

    return False


def check_json_test(test: dict, csaf_doc, returncode: int, messages) -> bool:
    """Check test result specified in converter-testcases-20-21 format.
    """

    # once a single check fails we can directly return False
    for condition in test["asserts"]:
        if condition["type"] == "errormsg":
            if "substring_matches" in condition:
                result = check_all_substrs_in(
                            condition.get("substring_matches"),
                            messages.get("errors"))

                if not result:
                    return False

        elif condition["type"] == "warningmsg":
            if "substring_matches" in condition:
                result = check_all_substrs_in(
                            condition.get("substring_matches"),
                            messages.get("warnings"))

                if not result:
                    return False

        elif condition["type"] == "jsonpath":

            nodes = jsonpath_rfc9535.find(condition['query'], csaf_doc)
            print(f"jsonpath_rfc9535.find({condition['query']}, csaf_doc) == "
                  f"{nodes}")

            if nodes.values() != condition["expected_result"]:
                return False


        elif condition["type"] == "success":
            if not condition["value"] == (returncode == 0):
                return False

        else:
            raise RuntimeError(
                f'condition["type"] == {condition["type"]} not implemented')

    # all checks were good
    return True

class RequirementLevel(Enum):
    MUST = 1
    SHALL = 1
    SHOULD = 2
    MAY = 3


def run_test(test, resultdir_name) -> (bool, RequirementLevel):
    test_from_json = type(test) == dict
    requirement_level = RequirementLevel.MUST  # default for both test types

    if test_from_json:
        input_filename = "input/" + test["input"]
        if "requirement_level" in test:
            if orl := getattr(
                    RequirementLevel, test["requirement_level"], None):
                requirement_level = orl
    else:
        input_filename = test

    output_filename = resultdir_name + "/tmp-out.json"
    completed_process = run([_CONV_BINARY, input_filename, output_filename],
                            capture_output=True, universal_newlines=True)

    print(completed_process)

    if len(completed_process.stderr) > 0:
        messages = json.loads(completed_process.stderr)

    print(messages)

    with open(output_filename, "rt", encoding="utf-8") as file:
        output_csaf_doc = json.load(file)

    if not test_from_json:
        if "testcase-1" in test:
            return (check_testcase1(
                       output_csaf_doc,
                       completed_process.returncode,
                       messages
                   ), requirement_level)

        if "testcase-2" in test:
            return (check_testcase2(
                       output_csaf_doc,
                       completed_process.returncode,
                       messages
                   ), requirement_level)

        if "testcase-3" in test:
            return (check_testcase3(
                       output_csaf_doc,
                       completed_process.returncode,
                       messages
                   ), requirement_level)
    else:
        return (check_json_test(
                    test,
                    output_csaf_doc,
                    completed_process.returncode,
                    messages
                ), requirement_level)

    return False


def load_tests(filename):
    with open(filename, "rt",  encoding="utf-8") as file:
        return json.load(file)

def main():
    tests = load_tests("./converter-testcases-20-21.json")

    print(f"Found {len(tests['converter_tests'])} in the spec file "
          f"and {len(_tests)} hardcoded.")
    print("running them ...\n")

    results = []
    # using a result directory that is automatically removed
    with tempfile.TemporaryDirectory() as resultdir_name:
        for test in _tests + tests["converter_tests"]:
            results.append(run_test(test, resultdir_name))
            print()

    print(f"Run {len(results)} test(s)...")
    print("Raw results vector:", repr(results))

    stats = {}
    for result in results:
        r_level = result[1]
        c = stats.get(r_level, {"PASSED": 0, "FAILED": 0})
        if result[0]:
            c["PASSED"] += 1
        else:
            c["FAILED"] += 1

        stats[r_level] = c

    print(f"\nStats:")
    for (key, value) in stats.items():
        print(key, value)

    print("Description of loaded tests:")
    for t in tests['converter_tests']:
        if "desc" in t:
            print(t["desc"])

if __name__ == "__main__":
    main()
