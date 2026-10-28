<!--
 This file is Free Software under the Apache-2.0 License
 without warranty, see README.md and LICENSES/Apache-2.0.txt for details.

 SPDX-License-Identifier: Apache-2.0

 SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
 Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
-->


# csaf-2.0-to-csaf-2.1
Test data for the CSAF 2.0 to CSAF 2.1 conversion

Goal: support implementations of "CSAF 2.0 to CSAF 2.1 Converter"
      by making tests available for testing this conformance profile.

**in development**

Some experimental tests are specified in `converter-testcases-20-21.json`,
which draw on input files from `input/`.

Tests come from
[CSAF v2.1 draft - development version - 9.1.18 Conformance Clause 18](https://github.com/oasis-tcs/csaf/blob/master/csaf_2.1/prose/share/csaf-v2.1-draft.md#conformance-clause-18-csaf-2-0-to-csaf-2-1-converter)

`prototype_runtests.py` is an experimental test runner to demonstrate
how a runner could work.


### `input/`
.. has CSAF 2.0 files.

There is one original file `isduba-2026-001.json`.
Many testcases were created
by running `prototype_modifier.py` on this or other original files.
(It seemed easier to construct good testcases by manipulating
existing CSAF 2.0 documents programmatically.)

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

This is implemented in `converter_replacement.py`, which is a prototype
that does a few hardcoded things like a converter might.


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

See specification and descriptions in
[csaf-converter-testcases-schema.json](csaf-converter-testcases-schema.json).

JSONPath [RFC 9535](https://www.rfc-editor.org/rfc/rfc9535) is used
as _query language_ to give the expected results for the `"type": "jsonpath"`
asserts.
The test runner implementation therefore needs an RFC 9535 compliant library.
(Spoiler: python3-jsonpatch-ng is _not_ one of those. When in doubt, there is a
[compliance test suite](https://github.com/jsonpath-standard/jsonpath-compliance-test-suite).)

The `requirement_level` of a test is optional to specify if the test
`MUST`, `SHOULD` or `MAY` succeed; when missing, it MUST.

The `warningmsg` and `errormsg` asserts require that a single message
contains all `substring_matches`. Their counterparts `no_warningmsg` and
`no_errormsg` require that no single message contains all of them.
With `"case_insensitive": true` these asserts ignore case.

### pattern for `converter_tests[].is_testing` elements in `converter-testcases-20-21.json`

```
<locator> ::= <ordinal> " " <list-item> {" " <list-item>}
<ordinal> ::= "Firstly" | "Secondly" | ... | "Tenthly"
<list-item> ::= (<bullet-list-item> | <numbered-list-item>) [<attachment>]
<bullet-list-item> ::= ("•" | "◦" | "▪") <element-number>
<numbered-list-item> ::= (<element-number> | <lowercase-letter>) "."
<attachment> ::= "(" <text> ")"
<text-selection> ::= "'" <text> "'" ["_" <element-number>]
<element-number> ::= "1" | "2" | ...
<coverage> ::= "0" | "1" | ... | "100"
```

The specifiers are applied from left to right, and each specifier is searched for within the range matched by the previous specifier.  
The `<element-number>` in `<text-selection>` specifies which occurrence of the string it refers to (starting at 1). When referring to the first occurrence this can be dropped.
In the JSON file the selector is then expressed like this: `[<locator>: string, [<text>: string, <element-number>: integer], <coverage>: integer]`