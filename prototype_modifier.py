#!/usr/bin/env python3
"""Be a dump CSAF 2.0 modifier that adds a simple `additional property`.

Only allowed input is a valid CSAF 2.0 file.
  If a different input is given, output is invalid.
  It is a VIVO concept (valid in valid out).
  The user is responsible to avoid IIIO (invalid in invalid out). ;)

Only do transformations that are _safe_,
so the output is as valid as the input.

Some internal test can be run by
    python3 -m doctest -v prototype_modifier.py

SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
"""
from copy import deepcopy
import datetime
import json
from pathlib import Path
import re
import sys

VERSION_INT_REGEXP = re.compile(r'^(0|[1-9][0-9]*)$') # from CSAF 2.0 3.1.11.1
VERSION_SEMVER_REGEXP = re.compile(
    r'^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$')  # from https://semver.org/ 2.2 FAQ


def next_major_revision(last_revision_number: str) -> str:
    """
    >>> next_major_revision('3')
    '4'
    >>> next_major_revision('1.12.3')
    '2.12.3'
    >>> next_major_revision('0.0.100-pre10+build2')
    '1.0.100-pre10+build2'
    """
    if VERSION_INT_REGEXP.fullmatch(last_revision_number):
        return str(int(last_revision_number) + 1)

    m = VERSION_SEMVER_REGEXP.match(last_revision_number)
    return str(int(m.group("major")) + 1) + m.string[m.start("minor") - 1:]


def rfc3339now():
    "Return now as rfc3339 in UTC without microseconds."
    return datetime.datetime.utcnow().isoformat(timespec='seconds') + "Z"


def modify1(csaf_doc: dict, filename: str, test_no:int) -> (dict, str):
    """Modifies a csaf document (as python dict) and calculates new id.

    Returns (pointer) to the old and dict and new filename.
    """
    # for easier access
    d = csaf_doc["document"]
    p = csaf_doc.get("product_tree", None)  # optional
    v = csaf_doc.get("vulnerabilities", None)  # optional

    now = rfc3339now()

    # change publisher
    org_publisher = d["publisher"]
    d["publisher"] = {
        "category": "other",
        "name": "Team csaf-testsuite/csaf-2.0-to-csaf-2.1",
        "namespace": "https://github.com/csaf-testsuite/csaf-2.0-to-csaf-2.1",
        }

    # prefix for new id
    id_prefix = f"testcase-{test_no}-" \
                + datetime.datetime.utcnow().strftime("%Y%m%d-%H%M-")

    # tracking section: bump version and put old publisher in revision summary
    dt = d["tracking"]
    old_id = dt["id"]
    new_id = id_prefix + old_id

    new_version = next_major_revision(dt["version"])

    dt["current_release_date"] = now
    dt["id"] = new_id
    dt["revision_history"].append({
        "date": now,
        "number": new_version,
        "summary": "created a test version from " + old_id + \
                   " from publisher: " + json.dumps(org_publisher),
        })
    dt["status"] = "final"  # we are at least version 1 so we must be final
    dt["version"] = new_version

    # move self references to external and invent new self
    for ref in d["references"]:
        if ref["category"] == "self":
            ref["category"] = "external"
            ref["summary"] = "original " + ref["summary"]

    d["references"].append({
        "category": "self",
        "summary": "plausible looking link to this specific run",
        "url": "https://github.com/csaf-testsuite/csaf-2.0-to-csaf-2.1/tmp/" \
                + new_id + ".json",
        })

    new_filename = Path(filename).parent / \
                   Path(id_prefix + Path(filename).name)


    return csaf_doc, new_filename


def _write_csaf_doc(filename, csaf_doc):
    print(f"writing {filename}")
    with open(filename, "wt",  encoding="utf-8") as file:
        json.dump(csaf_doc, file, indent=4, sort_keys=True)
        # write final line termination character, which json.dump does not,
        # but which is necessary to be a text file according to POSIX.
        file.write("\n")


def main(filename_str):
    filename = Path(filename_str)
    print(f"reading {filename}")

    with open(filename, "rt", encoding="utf-8") as file:
        csaf_doc = json.load(file)

    # test 1 additional property
    new_csaf_doc, new_filename = modify1(deepcopy(csaf_doc), filename, 1)
    new_csaf_doc["document"]["x_test_q7VQf"] = True
    _write_csaf_doc(new_filename, new_csaf_doc)

    # test 2 leap second
    new_csaf_doc, new_filename = modify1(deepcopy(csaf_doc), filename, 2)
    rh = new_csaf_doc["document"]["tracking"]["revision_history"]
    rh[0]["date"] = "2016-12-31T23:59:60Z" # a valid leap second
    if len(rh) > 2:
        rh[1]["date"] = "2026-12-31T23:59:60Z" # an invalid
    _write_csaf_doc(new_filename, new_csaf_doc)

    # test 3 branch category "legacy"
    new_csaf_doc, new_filename = modify1(deepcopy(csaf_doc), filename, 3)
    pb = new_csaf_doc["product_tree"]["branches"]
    pb.append({
        "category": "legacy",
        "name": "the attic for OurProduct",
        "branches": [{
            "category": "product_version",
            "name": "0.23.0",
            "product": {
                "name": "OurProduct outdated",
                "product_id": "ourproduct_old",
                },
            }],
        })

    # attempt to reference the old product
    if "vulnerabilities" in new_csaf_doc \
            and len(new_csaf_doc["vulnerabilities"]) > 0:
        vul1 = new_csaf_doc["vulnerabilities"][0]
        if "flags" in vul1 and len(vul1["flags"]) > 0:
            flags1 = vul1["flags"][0]
            if "product_ids" in flags1:
                flags1["product_ids"].append("ourproduct_old")

        if "product_status" in vul1:
            ps =  vul1["product_status"]
            if "known_not_affected" in ps:
                ps["known_not_affected"].append("ourproduct_old")

    _write_csaf_doc(new_filename, new_csaf_doc)


    # test 4 branches_t category appears multiple times along a path
    new_csaf_doc, new_filename = modify1(deepcopy(csaf_doc), filename, 4)
    pb = new_csaf_doc["product_tree"]["branches"]

    for i in range(len(pb)):
        org_branch = pb[i]
        if org_branch["category"] != 'product_family':
            new_branch = {
                 "category": org_branch["category"],
                 "name":  "super "+ org_branch["name"],
                 "branches": [org_branch],
                 }
            pb[i] = new_branch
            break

    _write_csaf_doc(new_filename, new_csaf_doc)


if __name__ == "__main__":
    main(sys.argv[1])
