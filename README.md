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
to experiment which data structure and interfaces are necessary.

### considerations

A typical run imagined:

1. Testing the input file, about being a CSAF 2.0 document.
   (By using existing validators.)
   If the input file is not a valid 2.0 document,
   a converter will not be required to produce a valid output file.

2. Run the converter, record return values, messages and files.

3. Compare all recorded results to expectations for that run.

4. Check that the output file is a valid CSAF 2.1 document
   (by using external CSAF validators).
   If the validators fail the mandatory tests, the converter failed.
