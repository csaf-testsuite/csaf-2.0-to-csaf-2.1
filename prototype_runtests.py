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

# the inputs of the hardcoded testcases 1 and 2 are invalid CSAF 2.0
_tests_options = {_tests[0]: ["force"], _tests[1]: ["force"]}

_CONV_BINARY = "./converter_replacement.py"

_CONV_OPTIONS: dict[str, list[str]] = {}


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


def check_all_substrs_in(substrs: list, msgs: list, *,
                         ignore_case: bool = False) -> bool:
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

    Case is only ignored on request.

    >>> check_all_substrs_in(["B","c"],["abC"])
    False
    >>> check_all_substrs_in(["B","c"],["abC"], ignore_case=True)
    True
    """
    if not substrs or not msgs:
        return False

    if ignore_case:
        substrs = [s.casefold() for s in substrs]
        msgs = [m.casefold() for m in msgs]

    for msg in msgs:
        missed_a_substring = False
        for substr in substrs:
            if substr not in msg:
                missed_a_substring = True
        if not missed_a_substring:
            return True

    return False


# assert type -> (kind of messages, whether a matching message is expected)
_MESSAGE_ASSERTS = {
    "errormsg": ("errors", True),
    "warningmsg": ("warnings", True),
    "no_errormsg": ("errors", False),
    "no_warningmsg": ("warnings", False),
}


def check_json_test(test: dict, csaf_doc, returncode: int, messages) -> bool:
    """Check test result specified in converter-testcases-20-21 format.
    """

    # once a single check fails we can directly return False
    for condition in test["asserts"]:
        if condition["type"] in _MESSAGE_ASSERTS:
            kind, expected = _MESSAGE_ASSERTS[condition["type"]]
            result = check_all_substrs_in(
                        condition["substring_matches"],
                        messages.get(kind),
                        ignore_case=condition.get("case_insensitive", False))

            if result != expected:
                return False

        elif condition["type"] == "jsonpath":
            if csaf_doc is None:
                return False

            nodes = jsonpath_rfc9535.find(condition['query'], csaf_doc)
            print(f"jsonpath_rfc9535.find({condition['query']}, csaf_doc) == "
                  f"{nodes.values()}")

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


def run_test(
    test: dict | str, resultdir_name: str
) -> tuple[bool | None, RequirementLevel]:
    """Run a single test, the first result is None if it was skipped."""
    test_from_json = type(test) == dict
    requirement_level = RequirementLevel.MUST  # default for both test types

    if test_from_json:
        input_filename = "input/" + test["input"]
        if "requirement_level" in test:
            if orl := getattr(
                    RequirementLevel, test["requirement_level"], None):
                requirement_level = orl
        options = test.get("converter_options", [])
    else:
        input_filename = test
        options = _tests_options.get(test, [])

    missing = [o for o in options if o not in _CONV_OPTIONS]
    if missing:
        print(f"skipping {input_filename}, the converter does not "
              f"provide the option(s): {', '.join(missing)}")
        return (None, requirement_level)
    option_args = [arg for o in options for arg in _CONV_OPTIONS[o]]

    output_path = Path(resultdir_name) / "tmp-out.json"
    output_path.unlink(missing_ok=True)
    completed_process = run(
            [_CONV_BINARY, *option_args, input_filename, str(output_path)],
            capture_output=True, universal_newlines=True)

    print(completed_process)

    messages = json.loads(completed_process.stderr) if completed_process.stderr else {}

    print(messages)

    output_csaf_doc = None
    if output_path.is_file():
        with output_path.open(encoding="utf-8") as file:
            output_csaf_doc = json.load(file)
    elif completed_process.returncode == 0 or not test_from_json:
        print(f"missing converter output: {output_path}")
        return (False, requirement_level)

    if test_from_json:
        result = check_json_test(
            test, output_csaf_doc, completed_process.returncode, messages
        )
    else:
        checker = {
            _tests[0]: check_testcase1,
            _tests[1]: check_testcase2,
            _tests[2]: check_testcase3,
        }.get(test)
        result = checker is not None and checker(
            output_csaf_doc, completed_process.returncode, messages
        )

    return (result, requirement_level)


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
        c = stats.get(r_level, {"PASSED": 0, "FAILED": 0, "SKIPPED": 0})
        if result[0] is None:
            c["SKIPPED"] += 1
        elif result[0]:
            c["PASSED"] += 1
        else:
            c["FAILED"] += 1

        stats[r_level] = c

    print(f"\nStats:")
    for (key, value) in stats.items():
        print(key, value)

    print("Details of loaded tests:")
    for i,t in enumerate(tests['converter_tests'], 1):
        if "is_testing" in t:
            is_testing = ", ".join([json.dumps(x, ensure_ascii=False) for x in t["is_testing"]])
            remark = f": {t['remark']}" if "remark" in t else ""
            print(f"{i:2d}:", f"{is_testing}{remark}")

if __name__ == "__main__":
    main()
