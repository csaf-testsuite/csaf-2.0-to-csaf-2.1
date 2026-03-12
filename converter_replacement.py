#!/usr/bin/env python3
"""Do some hardwired CSAF 2.0 -> 2.1 converter actions to test test_runners.

Interface:
    * Issue collected warnings and errors to stderr in JSON
    * Indicate via exit() value: 0 for success; >0 for failure

SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
"""
import json
import sys

_warnings = []

def warn(msg):
    _warnings.append(msg)


def main(input_filename, output_filename):
    print("doing hardcoded conversions "
          f"`{input_filename}` -> `{output_filename}`")

    with open(input_filename, "rt", encoding="utf-8") as file:
        csaf_doc = json.load(file)

    # for easier access
    d = csaf_doc["document"]

    d["csaf_version"] = "2.1"


    warnings = []
    errors = []

    # 9.1.18 Conformance Clause 18: CSAF 2.0 to CSAF 2.1 Converter
    # toplevel requirement
    additional_property_name = "x_test_q7VQf"
    if additional_property_name in d:
        warnings.append(
            f"found an additional property `{additional_property_name}`"
            " which will be not converted."
            )
        del d[additional_property_name]

    #errors.append("could not create a valid products tree "
    #              "with _invalid path_, _original_ and _new value:")


    rh = d["tracking"]["revision_history"]

    for rev in rh:
        if rev["date"].endswith("T23:59:60Z"):
            status = "valid"
            if rev["date"] != "2016-12-31T23:59:60Z":
                status = "invalid"

            warnings.append(
                    f"Found {status} leap second date-time {rev['date']}, "
                    "replaced it, because leap seconds are probited "
                    "in CSAF 2.1."
                )
            rev["date"] = rev["date"][:-3] + "59.999999Z"

    messages = {}
    if len(errors) > 0:
        messages["errors"] = errors
    if len(warnings) > 0:
        messages["warnings"] = warnings

    json.dump(messages, sys.stderr, indent=4)
    sys.stderr.write("\n")  # write final line termination character

    if len(errors) > 0:
        print("aborting because of error")
        sys.exit(1)

    with open(output_filename, "wt",  encoding="utf-8") as file:
        json.dump(csaf_doc, file, indent=4, sort_keys=True)
        file.write("\n")  # write final line termination character


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
