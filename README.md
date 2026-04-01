<!--
 This file is Free Software under the Apache-2.0 License
 without warranty, see README.md and LICENSES/Apache-2.0.txt for details.

 SPDX-License-Identifier: Apache-2.0

 SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
 Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
-->


# csaf-2.0-to-csaf-2.1
Test data for the CSAF 2.0 to CSAF 2.1 conversion

**in development**

Goal: support implementations of "CSAF 2.0 to CSAF 2.1 Converter"
      by making tests available for testing this conformance profile.


Tests come from
[CSAF v2.1 draft - development version - 9.1.18 Conformance Clause 18](https://github.com/oasis-tcs/csaf/blob/master/csaf_2.1/prose/share/csaf-v2.1-draft.md#conformance-clause-18-csaf-2-0-to-csaf-2-1-converter)

Running `prototype_runtests.py` will execute some hardcoded things
to experiment which data structures and interfaces are necessary.


### `input/`
.. has CSAF 2.0 files.

There is one original file `isduba-2026-001.json`.

Most other testcases were created
by runing `prototype_modifier.py` on this or other original files.

Each time the original is linked as
`$.document.references[?(@.category=='external')]`.


### converter "interface"

For experimentation the following interface to a converter is proposed:

Arguments to binary: `inputfile`, `outputfile`

Exitcode: 0 for success; >0 for failure

Diagnostics: write a JSON object to stderr with optionally
warnings and errors as a list of strings.

```
{ "warnings": [],
  "errors":   [] }
```

This is implemented in `converter_replacement.py`, which does
a few hardcoded things like a converter would.


### considerations

A typical run of testing a converter imagined:

1. Testing the input file, about being a CSAF 2.0 document.
   (By using existing validators.)
   If the input file is not a valid 2.0 document,
   a converter will not be required to produce a valid output file.

2. Run the converter, record return values, messages and files.

3. Compare all recorded results to expectations for that run.

4. Check that the output file is a valid CSAF 2.1 document
   (by using external CSAF validators).
   If the validators fail the mandatory tests, the converter failed.

### discovered invariants

A number of invariants could be tested on all converter results.
They are given by a JSONPath pattern and expected output. Examples:

```json
{ "type": "jsonpath",
   "query": "$..[?search(@.date, ':60[Z+-]')].date",
   "expected_result": [],
   "comment": "The I-Regular expression given in the JSONPath will match all leap seconds that can appear related to software, according to https://en.wikipedia.org/wiki/List_of_tz_database_time_zones (checked 2026-03-31), as Dublin Mean Time (UTC−00:25:21) was abolished 1916."
}
```

```json
{ "type": "jsonpath",
  "query": "$.product_tree.branches..[?(@.category=='legacy')]",
  "expected_result": []
}
```

### format of `converter-testcases-20-21.json`

JSONPath [RFC 9535](https://www.rfc-editor.org/rfc/rfc9535) is used
as _query language_ to give the expected results for the `"type": "jsonpath"`
asserts.

The test runner implementation therefor needs an RFC 9535 compliant library.
(Spoiler: python3-jsonpatch-ng is _not_ on of those. When in doubt, there is a
[compliance test suite](https://github.com/jsonpath-standard/jsonpath-compliance-test-suite).)

The `other_requirement_level" is optional to specify if the test
`MUST`, `SHOULD` or `MAY` succeed; when missing it is "MUST".

**TODO**
