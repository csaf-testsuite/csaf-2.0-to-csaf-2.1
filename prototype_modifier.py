#!/usr/bin/env python3
"""Be a dump CSAF 2.0 modifier that adds a simple `additional property`.

Only allowed input is a valid CSAF 2.0 file.
(If a different input is given, output is undefined.
The user is responsible.)

And only do transformations that are _safe_
so the output is as valid as the input.

SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
"""
import json
from pathlib import Path
import sys

def main(filename_str):
    filename = Path(filename_str)
    print(f"reading {filename}")

    with open(filename, "rt", encoding="utf-8") as file:
        csaf_doc = json.load(file)

    sys.stderr.write("modification funcationality not implemented yet\n")
    # TODO change publisher

    # TODO move self reference to external and invent new self

    # TODO calculate new document ID
    new_filename = Path(filename).parent / \
                   Path("yo-" + Path(filename).name)

    # TODO do modification

    print(f"writing {new_filename}")
    with open(new_filename, "wt",  encoding="utf-8") as file:
        json.dump(csaf_doc, file, indent=4, sort_keys=True)
        file.write("\n")  # write final line termination character

if __name__ == "__main__":
    main(sys.argv[1])
