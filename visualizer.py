#!/usr/bin/env python3

"""Create HTML visualization for CSAF converter-test selectors.
Has additional options for creating an HTML file with an interactive selector and for testing selector pattern.
Use --help for help.

By default when run from the command line the script downloads the CSAF specifications!

SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
"""

import argparse
import hashlib
import itertools
import json
import logging
import operator
import re
import sys
import tempfile
import urllib.error
import urllib.request
import xml.etree.ElementTree as etree  # ruff: ignore[camelcase-imported-as-lowercase, unconventional-import-alias]
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from enum import Enum
from functools import partial
from html.parser import HTMLParser
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from markdown import Markdown
from markdown.extensions import Extension
from markdown.preprocessors import Preprocessor
from markdown.treeprocessors import Treeprocessor

REVISIONS = {
    "2.1-csd02": "https://docs.oasis-open.org/csaf/csaf/v2.1/csd02/csaf-v2.1-csd02.md",
    "2.1-csd03": "https://docs.oasis-open.org/csaf/csaf/v2.1/csd03/csaf-v2.1-csd03.md",
}

COMMIT_TAG_PATTERN = re.compile(r"^[0-9a-f]{6,40}$")
REVISION_TEMPLATE = "https://raw.githubusercontent.com/oasis-tcs/csaf/{tag}/csaf_2.1/prose/share/csaf-v2.1-draft.md"

SECTION_ANCHOR = "conformance-clause-18-csaf-2-0-to-csaf-2-1-converter"
MARKDOWN_EXTENSIONS = ("extra", "mdx_truly_sane_lists")

_TOP_LEVEL_LIST_MARKER = re.compile(r"^[*+-][ \t]+")
_QUOTED_LIST_MARKER = re.compile(r"^(?P<indent>[ \t]*)>[ \t]+[*+-][ \t]+")

# https://github.com/oasis-tcs/csaf/blob/master/csaf_2.1/prose/share/style/base.css
COMMON_CSS = """blockquote {
    background-color: #f0f0f0;
    padding-left: 10px;
    border-left: solid lightgray 6px;
}
table, th, td {
    border: 1pt solid black;
    padding: 6pt 6pt;
    text-align: left;
    vertical-align: top;
}
th {
    color: #ffffff;
    background-color: #446CAA;
}
table {
    border-collapse: collapse;
    border-spacing: 0;
    width: 100%;
    display: table;
    font-size: 12pt;
    margin-top: 6pt;
}"""

COVERAGE_CSS = """.coverage {
    background-color: color-mix(
        in oklch,
        oklch(0.55 0.12 55) calc(100% - var(--coverage)),
        oklch(0.76 0.18 140) var(--coverage)
    );
}
.coverage-full {
    background-color: #60f060;
}"""

SELECTOR_SCRIPT_PATH = Path(__file__).with_name("selector_script.js")

logger = logging.getLogger(__name__)


class _CommonMarkListBoundaryPreprocessor(Preprocessor):
    """Add block boundaries which Markdown requires before lists.

    For example, the parser treats the marker in this GFM input as part
    of the paragraph because the continued line is indented::

        A paragraph
          continued here
        * A list item

    This preprocessor inserts an empty line before the list item so the
    parser produces a paragraph followed by a list.
    """

    def run(self, lines: list[str]) -> list[str]:  # ruff:ignore[no-self-use]
        """Return source lines with separating lines inserted."""
        result: list[str] = []

        for line in lines:
            previous = result[-1] if result else ""

            # A zero-indented marker after an indented continuation is a new
            # top-level item in CommonMark/GFM
            if _TOP_LEVEL_LIST_MARKER.match(line) and previous.strip() and previous[:1].isspace():
                result.append("")

            else:
                quoted_marker = _QUOTED_LIST_MARKER.match(line)
                if (
                    quoted_marker
                    and previous.strip()
                    # Do not add another separator if the blockquote already
                    # contains an explicit blank quoted line.
                    and not re.match(r"^[ \t]*>[ \t]*$", previous)
                    # Consecutive quoted items already belong to a list.
                    and not _QUOTED_LIST_MARKER.match(previous)
                ):
                    # A completely empty line would end the blockquote. Insert
                    # an empty quoted line instead, preserving the quote.
                    result.append(f"{quoted_marker.group('indent')}>")

            result.append(line)

        return result


class _AdjacentUnorderedListTreeprocessor(Treeprocessor):
    """Merge adjacent lists.

    Example::

        <ul><li>first</li></ul>
        <ul><li>second</li></ul>

    Becomes::

        <ul><li>first</li><li>second</li></ul>

    A paragraph, heading, or other element between two lists prevents merging.
    """

    @staticmethod
    def _tag(element: etree.Element) -> str:
        tag = element.tag
        return tag.lower() if isinstance(tag, str) else ""

    def run(self, root: etree.Element) -> etree.Element:
        """Merge adjacent ``ul`` siblings in the tree."""
        for parent in list(root.iter()):
            previous_list: etree.Element | None = None
            for child in list(parent):
                if self._tag(child) != "ul":
                    previous_list = None
                    continue
                if previous_list is None or (previous_list.tail or "").strip():
                    previous_list = child
                    continue

                # Do the merge by moving the child list items into the previous list
                # and removing the child list.
                for list_item in list(child):
                    previous_list.append(list_item)
                previous_list.tail = child.tail
                parent.remove(child)

        return root


class _CommonMarkListBoundaryExtension(Extension):
    """Register the CommonMark/GFM list compatibility fix."""

    def extendMarkdown(  # ruff:ignore[invalid-function-name,no-self-use]
        self,
        md: Markdown,
    ) -> None:
        # Run after the other preprocessors (HtmlBlockPreprocessor has priority 20).
        # https://python-markdown.github.io/reference/markdown/preprocessors/
        md.preprocessors.register(
            _CommonMarkListBoundaryPreprocessor(md),
            "commonmark_list_boundaries",
            15,
        )
        # Run after the other treeprocessors but before the selector processor
        # (priority -1).
        md.treeprocessors.register(
            _AdjacentUnorderedListTreeprocessor(md),
            "merge_adjacent_unordered_lists",
            0,
        )


# https://stackoverflow.com/questions/64695883/extracting-text-parse-text-with-html-parser-python
# https://docs.python.org/3/library/html.parser.html
class _HTMLFragmentParser(HTMLParser):
    """Collect visible text and anchor IDs from a raw HTML fragment."""

    def __init__(self, anchor: str | None = None) -> None:
        super().__init__(convert_charrefs=True)
        self.anchor = anchor
        self.found_anchor = False
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.anchor is None or tag.lower() != "a":
            return
        if any(name.lower() == "id" and value == self.anchor for name, value in attrs):
            self.found_anchor = True

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def _parse_html_fragment(fragment: str, anchor: str | None = None) -> tuple[str, bool]:
    """Return visible text and whether ``fragment`` contains ``anchor``.

    If ``anchor`` is ``None``, the returned anchor flag is ``False``.
    """
    parser = _HTMLFragmentParser(anchor)
    parser.feed(fragment)
    parser.close()
    return "".join(parser.text), parser.found_anchor


class ListItemKind(Enum):
    """Kinds of list item understood by locators."""

    BULLET = "bullet"  # <ul>
    NUMBERED = "numbered"  # <ol>


@dataclass(frozen=True, slots=True)
class ListItem:
    """One parsed ``<list-item>`` in a locator."""

    kind: ListItemKind
    element_number: int  # starts at 1, not 0


@dataclass(frozen=True, slots=True)
class TextSelection:
    """A parsed ``<text-selection>`` and its ``<element-number>``."""

    text: str
    element_number: int  # starts at 1, not 0


@dataclass(frozen=True, slots=True)
class ParsedLocator:
    """A parsed ``<locator>`` containing an ordinal and list items."""

    ordinal: str
    list_items: tuple[ListItem, ...]


@dataclass(frozen=True, slots=True)
class ParsedSelector:
    """A parsed selector and its optional text selection and coverage."""

    locator: ParsedLocator
    text_selection: TextSelection | None
    coverage: int | None


@dataclass(frozen=True, slots=True)
class SelectorRequest:
    """A testcase selector that should be resolved and highlighted."""

    input_file: str
    selector: list[object]


@dataclass(frozen=True, slots=True)
class TextSegment:
    """A character range in one tree text slot."""

    element: etree.Element
    # Text can be in element.text or in child.tail
    attribute: Literal["text", "tail"]
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class SelectorMatch:
    """A resolved selector and the tree text ranges it covers."""

    element: etree.Element  # <li> elem
    text: str
    segments: tuple[TextSegment, ...]
    coverage: int


@dataclass(frozen=True, slots=True)
class ResolvedSelector:
    """Resolution result for a testcase selector."""

    input_file: str
    selector: list[object]
    match: SelectorMatch | None

    @property
    def is_resolved(self) -> bool:
        """Return whether the selector matched the parsed document."""
        return self.match is not None


@dataclass(frozen=True, slots=True)
class RenderedSection:
    """HTML section output and selector results."""

    html: str
    section_found: bool
    selectors: tuple[ResolvedSelector, ...]


class MarkdownSelector:
    """Resolve selectors against the element tree."""

    ORDINALS = (
        "Firstly",
        "Secondly",
        "Thirdly",
        "Fourthly",
        "Fifthly",
        "Sixthly",
        "Seventhly",
        "Eighthly",
        "Ninthly",
        "Tenthly",
    )
    MAX_COVERAGE = 100

    LIST_ITEM_PATTERN = re.compile(
        r"(?:"
        r"(?P<bullet>[•◦▪])(?P<bullet_element_number>[1-9][0-9]*)"
        r"|(?:(?P<numbered_element_number>[1-9][0-9]*)|(?P<letter>[a-z]))\."
        r")"
        r"(?:\([^()]+\))?"
    )

    _BLOCK_TAGS = frozenset({"blockquote", "div", "li", "ol", "p", "pre", "table", "ul"})

    def __init__(self, root: etree.Element) -> None:
        self.root = root
        self.section = self._find_section()

    @staticmethod
    def _tag(element: etree.Element) -> str:
        """Return a lower-case element tag name."""
        tag = element.tag
        if not isinstance(tag, str):
            return ""
        return tag.lower()

    @classmethod
    def _is_heading(cls, element: etree.Element) -> bool:
        tag = cls._tag(element)
        return len(tag) == 2 and tag[0] == "h" and tag[1] in "123456"

    @classmethod
    def _list_item_kind(cls, element: etree.Element) -> ListItemKind | None:
        tag = cls._tag(element)
        if tag == "ul":
            return ListItemKind.BULLET
        if tag == "ol":
            return ListItemKind.NUMBERED
        return None

    def _find_section(self) -> tuple[etree.Element, ...]:
        """Return blocks from the first parsed heading to the next heading.

        ``render_markdown_section`` crops the markdown at the configured anchor
        before parsing, so the target heading is the first heading in the tree.
        Splitting is then done at the HTML element level and not on the markdown
        source.
        Returns an empty tuple if the tree contains no heading.
        """
        children = list(self.root)
        # First heading, so the one with the anchor ID
        heading_index = next(
            (index for index, element in enumerate(children) if self._is_heading(element)),
            None,
        )
        if heading_index is None:
            return ()

        # Find the next heading after the first one, or the end of the tree.
        end = next(
            (index for index in range(heading_index + 1, len(children)) if self._is_heading(children[index])),
            len(children),
        )
        return tuple(children[:end])

    def keep_section_only(self) -> None:
        """Remove parsed blocks outside the configured section."""
        keep = set(self.section)
        for element in list(self.root):
            if element not in keep:
                self.root.remove(element)

    @staticmethod
    def _parse_text_selection(value: object) -> TextSelection | None:
        """Parse one JSON ``textSelection`` value."""
        match value:
            case [str(text)] if text:
                return TextSelection(text=text, element_number=1)
            case [str(text), int(element_number)] if text and element_number >= 1:
                return TextSelection(text=text, element_number=element_number)
            case _:
                return None

    @classmethod
    def _parse_coverage(cls, value: object) -> int | None:
        """Parse coverage."""
        if not isinstance(value, int) or isinstance(value, bool):  # bool is a subclass of int
            return None
        return value

    def _parse_selector_parts(
        self,
        selector: object,
    ) -> tuple[str, TextSelection | None, int | None] | None:
        """Parse the positional values in the JSON selector array."""
        match selector:
            case [str(locator_text)]:
                return locator_text, None, None
            case [str(locator_text), list(text_selection_value)]:
                text_selection = self._parse_text_selection(text_selection_value)
                return (locator_text, text_selection, None) if text_selection is not None else None
            case [str(locator_text), int(coverage_value)]:
                coverage = self._parse_coverage(coverage_value)
                return (locator_text, None, coverage) if coverage is not None else None
            case [str(locator_text), list(text_selection_value), int(coverage_value)]:
                text_selection = self._parse_text_selection(text_selection_value)
                coverage = self._parse_coverage(coverage_value)
                if text_selection is not None and coverage is not None:
                    return locator_text, text_selection, coverage
                return None
            case _:
                return None

    def _parse_selector(self, selector: object) -> ParsedSelector | None:
        """Parse a selector.

        Returns ``None`` if its locator, list-item element numbers, text
        selection or coverage is invalid.
        """
        parts = self._parse_selector_parts(selector)
        if parts is None:
            return None
        locator_text, text_selection, coverage = parts

        ordinal = next(
            (
                candidate
                for candidate in self.ORDINALS
                if locator_text[: len(candidate)].lower() == candidate.lower()
                and (len(locator_text) == len(candidate) or not locator_text[len(candidate)].isalpha())
            ),
            None,
        )
        if ordinal is None:
            return None

        list_items_text = locator_text[len(ordinal) :]
        list_items: list[ListItem] = []
        cursor = 0

        for match in self.LIST_ITEM_PATTERN.finditer(list_items_text):
            separator = list_items_text[cursor : match.start()]
            if not separator or not separator.isspace():
                return None

            if match.group("bullet"):
                list_item = ListItem(
                    ListItemKind.BULLET,
                    int(match.group("bullet_element_number")),
                )
            elif match.group("numbered_element_number"):
                list_item = ListItem(
                    ListItemKind.NUMBERED,
                    int(match.group("numbered_element_number")),
                )
            else:
                letter = match.group("letter").lower()
                list_item = ListItem(ListItemKind.NUMBERED, ord(letter) - ord("a") + 1)

            if list_item.element_number < 1:
                return None
            list_items.append(list_item)
            cursor = match.end()

        if list_items_text[cursor:] or not list_items:
            return None

        return ParsedSelector(
            locator=ParsedLocator(
                ordinal=ordinal,
                list_items=tuple(list_items),
            ),
            text_selection=text_selection,
            coverage=coverage,
        )

    @staticmethod
    def _normalize_plain_text(text: str) -> str:
        """Collapse visible whitespace."""
        return re.sub(r"\s+", " ", text).strip()

    @staticmethod
    def _slot_units(
        element: etree.Element,
        attribute: Literal["text", "tail"],
    ) -> Iterator[tuple[str, TextSegment]]:
        """Yield visible characters and their ranges from one tree text slot."""
        # Tree has no separate text-node children. Text before its
        # first child is in ``element.text``. Text following an element is in
        # that element's ``tail``. Treat them individually
        raw: str = getattr(element, attribute) or ""

        # If the markdown has inline html, we might have to handle it in the future
        # https://python-markdown.github.io/reference/markdown/inlinepatterns/#markdown.inlinepatterns.HtmlInlineProcessor

        for index, char in enumerate(raw):
            yield char, TextSegment(element, attribute, index, index + 1)

    def _visible_units(self, element: etree.Element) -> Iterator[tuple[str, TextSegment | None]]:
        """Yield visible text in document order."""
        # Document order is: the element's own text, then each
        # child's contents followed by that child's tail.
        yield from self._slot_units(element, "text")

        for child in element:
            is_block = self._tag(child) in self._BLOCK_TAGS
            # Adjacent block elements are visually separated. Insert artificial
            # space in here as to not concatenate the last character of the previous
            # block with the first character of the next block.
            if is_block:
                yield " ", None
            yield from self._visible_units(child)
            if is_block:
                yield " ", None

            # A tail belongs to the child node but appears after the child's
            # closing tag, so it's emitted afterwards
            yield from self._slot_units(child, "tail")

    def _plain_text_with_positions(
        self,
        element: etree.Element,
    ) -> tuple[str, list[TextSegment | None]]:
        """Return plain text and corresponding tree positions."""
        plain: list[str] = []
        positions: list[TextSegment | None] = []

        for char, position in self._visible_units(element):
            if char.isspace():
                if not plain or plain[-1] == " ":  # skip leading and consecutive whitespace
                    continue
                char = " "
            plain.append(char)
            positions.append(position)

        # Leading whitespace was skipped above. Remove trailing whitespace here
        while plain and plain[-1] == " ":
            plain.pop()
            positions.pop()

        return "".join(plain), positions

    @staticmethod
    def _merge_segments(positions: Iterable[TextSegment | None]) -> tuple[TextSegment, ...]:
        """Merge adjacent character positions."""
        merged: list[TextSegment] = []

        for position in positions:
            if position is None:
                continue
            if (
                merged
                and merged[-1].element is position.element
                and merged[-1].attribute == position.attribute
                and position.start <= merged[-1].end
            ):
                previous = merged[-1]
                merged[-1] = TextSegment(
                    previous.element,
                    previous.attribute,
                    previous.start,
                    max(previous.end, position.end),
                )
            else:
                merged.append(position)

        return tuple(merged)

    def _ordinal(self, element: etree.Element) -> str | None:
        """Return the ordinal beginning paragraph.

        Returns ``None`` if ``element`` is not a paragraph or does not begin
        with a supported ordinal.
        """
        if self._tag(element) != "p":
            return None

        text, _ = self._plain_text_with_positions(element)
        prefix, separator, _rest = text.partition(",")
        if not separator:
            return None

        prefix = prefix.strip().lower()
        return next((ordinal for ordinal in self.ORDINALS if ordinal.lower() == prefix), None)

    def _ordinal_range(self, ordinal: str) -> tuple[etree.Element, ...]:
        """Return parsed blocks below ``ordinal`` and before the next ordinal.

        Returns an empty tuple if the ordinal is not present.
        """
        ordinal_indexes = [
            (index, found) for index, element in enumerate(self.section) if (found := self._ordinal(element)) is not None
        ]
        selected = next(
            (position for position, (_index, found) in enumerate(ordinal_indexes) if found.lower() == ordinal.lower()),
            None,
        )
        if selected is None:
            return ()

        start = ordinal_indexes[selected][0] + 1
        end = ordinal_indexes[selected + 1][0] if selected + 1 < len(ordinal_indexes) else len(self.section)
        return self.section[start:end]

    def _top_level_list_items(
        self,
        elements: Iterable[etree.Element],
        kind: ListItemKind,
    ) -> list[etree.Element]:
        """Return list items not nested inside another list item."""
        items: list[etree.Element] = []

        def visit(element: etree.Element) -> None:
            list_item_kind = self._list_item_kind(element)
            if list_item_kind is not None:
                if list_item_kind is kind:
                    items.extend(child for child in element if self._tag(child) == "li")
                return

            for child in element:
                visit(child)

        for element in elements:
            visit(element)
        return items

    def _nested_list_items(self, item: etree.Element, kind: ListItemKind) -> list[etree.Element]:
        """Return list items one list level below ``item``."""
        items: list[etree.Element] = []

        def visit(element: etree.Element) -> None:
            list_item_kind = self._list_item_kind(element)
            if list_item_kind is not None:
                if list_item_kind is kind:
                    items.extend(child for child in element if self._tag(child) == "li")
                return

            for child in element:
                # A nested list inside a descendant list item belongs to a
                # deeper list-item level and must not be considered here.
                if self._tag(child) != "li":
                    visit(child)

        for child in item:
            visit(child)
        return items

    @staticmethod
    def _nth(items: list[etree.Element], list_item: ListItem) -> etree.Element | None:
        """Return the list item identified by its one-based element number.

        Returns ``None`` if the element number exceeds the number of items.
        """
        if list_item.element_number > len(items):
            return None
        return items[list_item.element_number - 1]

    def resolve(self, selector: list[object]) -> SelectorMatch | None:
        """Resolve a selector against the section.

        Returns ``None`` if the selector is invalid, its locator cannot identify
        a list item, or its requested text-selection element cannot be found.
        """
        parsed_selector = self._parse_selector(selector)
        if parsed_selector is None or not self.section:
            return None
        locator = parsed_selector.locator

        # Limit the search range to only the block below e.g. ``Secondly``
        search_range = self._ordinal_range(locator.ordinal)
        if not search_range:
            return None

        # Resolve the locator one list level at a time.
        selected: etree.Element | None = None
        siblings = self._top_level_list_items(search_range, locator.list_items[0].kind)

        for index, list_item in enumerate(locator.list_items):
            if index >= 1:
                if selected is None:
                    return None
                siblings = self._nested_list_items(selected, list_item.kind)

            selected = self._nth(siblings, list_item)
            if selected is None:
                return None

        if selected is None:
            return None

        plain, positions = self._plain_text_with_positions(selected)

        # With no text selection, the complete list item is highlighted
        if parsed_selector.text_selection is None:
            return SelectorMatch(
                element=selected,
                text=plain,
                segments=self._merge_segments(positions),
                coverage=parsed_selector.coverage if parsed_selector.coverage is not None else self.MAX_COVERAGE,
            )

        needle = self._normalize_plain_text(parsed_selector.text_selection.text)
        if not needle:
            return None

        # ``element_number`` is the occurrence (starting at 1) of the requested
        # text. Advancing by the full match length counts distinct occurrences
        search_from = 0
        match_index = -1
        for _ in range(parsed_selector.text_selection.element_number):
            match_index = plain.find(needle, search_from)
            if match_index == -1:
                return None
            search_from = match_index + len(needle)

        matched_positions = positions[match_index : match_index + len(needle)]
        return SelectorMatch(
            element=selected,
            text=plain[match_index : match_index + len(needle)],
            segments=self._merge_segments(matched_positions),
            coverage=parsed_selector.coverage if parsed_selector.coverage is not None else self.MAX_COVERAGE,
        )


# https://Markdown.github.io/extensions/api/
# https://Markdown.github.io/reference/markdown/treeprocessors/
class _SelectorTreeprocessor(Treeprocessor):
    """Resolve selectors, add highlight spans, and retain only the target section."""

    def __init__(
        self,
        md: Markdown,
        requests: tuple[SelectorRequest, ...],
    ) -> None:
        super().__init__(md)
        self.requests = requests
        self.section_found = False
        self.results: tuple[ResolvedSelector, ...] = ()

    @staticmethod
    def _annotation_span(result: ResolvedSelector, text: str, coverage: int) -> etree.Element:
        """Build a highlight span for a resolved selector."""
        coverage_class = "coverage-full" if coverage == MarkdownSelector.MAX_COVERAGE else "coverage-partial"
        span = etree.Element(
            "span",
            {
                "class": f"coverage {coverage_class}",
                "data-coverage": str(coverage),
                "data-file": result.input_file,
                "data-selector": json.dumps(result.selector, ensure_ascii=False),
                "style": f"--coverage: {coverage}%",
            },
        )
        span.text = text
        return span

    def _nested_annotation_span(
        self,
        text: str,
        active: list[tuple[int, ResolvedSelector]],
    ) -> etree.Element:
        """Nest spans when selector highlights overlap and add tooltips."""
        coverage_values = [result.match.coverage for _annotation_id, result in active if result.match is not None]
        total_coverage = sum(coverage_values)
        coverage = min(max(total_coverage, 0), MarkdownSelector.MAX_COVERAGE)
        if coverage != total_coverage:
            logger.warning(
                "Coverage values %s for highlighted segment %r sum to %d; capped to %d.",
                coverage_values,
                text,
                total_coverage,
                coverage,
            )

        tooltip_lines = [f"Coverage: {coverage}%"]
        for _annotation_id, result in sorted(active, key=operator.itemgetter(0)):
            tooltip_lines.extend((
                "",
                f"File: {result.input_file}",
                json.dumps(result.selector, ensure_ascii=False),
            ))
        tooltip_text = "\n".join(tooltip_lines)

        child: etree.Element | None = None

        for _annotation_id, result in sorted(active, reverse=True, key=operator.itemgetter(0)):
            span = self._annotation_span(result, text if child is None else "", coverage)
            span.set("title", tooltip_text)
            if child is not None:
                span.append(child)
            child = span

        if child is None:
            msg = "active must contain at least one annotation"
            raise ValueError(msg)
        return child

    def _replace_slot(
        self,
        element: etree.Element,
        attribute: Literal["text", "tail"],
        marks: list[tuple[int, int, int, ResolvedSelector]],
        parents: dict[etree.Element, etree.Element],
    ) -> None:
        """Replace text slot with text and annotation spans."""
        raw = getattr(element, attribute) or ""
        boundaries = sorted({
            0,
            len(raw),
            *(start for start, _end, _id, _result in marks),
            *(end for _start, end, _id, _result in marks),
        })

        head = ""
        nodes: list[etree.Element] = []

        for start, end in itertools.pairwise(boundaries):
            if start == end:
                continue
            fragment = raw[start:end]
            active = [
                (annotation_id, result)
                for mark_start, mark_end, annotation_id, result in marks
                if mark_start <= start and end <= mark_end
            ]

            if active:
                nodes.append(self._nested_annotation_span(fragment, active))
            elif nodes:
                nodes[-1].tail = (nodes[-1].tail or "") + fragment
            else:
                head += fragment

        if attribute == "text":
            element.text = head or None
            for index, node in enumerate(nodes):
                element.insert(index, node)
            return

        # For attribute == "tail":
        parent = parents.get(element)
        if parent is None:
            element.tail = head or None
            return

        element.tail = head or None
        insert_at = list(parent).index(element) + 1
        for node in nodes:
            parent.insert(insert_at, node)
            insert_at += 1

    def _apply_annotations(self, root: etree.Element) -> None:
        """Apply resolved selector ranges to the parsed tree."""
        slots: dict[
            tuple[int, str],
            tuple[
                etree.Element,
                Literal["text", "tail"],
                list[tuple[int, int, int, ResolvedSelector]]  # (start_offset, end_offset, annotation_id, resolved_selector)
            ]
        ] = {}  # fmt: skip

        for annotation_id, result in enumerate(self.results):
            if result.match is None:
                continue
            for segment in result.match.segments:
                key = (id(segment.element), segment.attribute)
                if key not in slots:
                    slots[key] = (segment.element, segment.attribute, [])
                slots[key][2].append((segment.start, segment.end, annotation_id, result))

        # Child to parent map to access the parent from a child
        parents = {child: parent for parent in root.iter() for child in parent}
        for element, attribute, marks in slots.values():
            self._replace_slot(element, attribute, marks, parents)

    # Called by Markdown.convert()
    def run(self, root: etree.Element) -> etree.Element:
        markdown_selector = MarkdownSelector(root)
        self.section_found = bool(markdown_selector.section)

        self.results = tuple(
            ResolvedSelector(
                input_file=request.input_file,
                selector=request.selector,
                match=markdown_selector.resolve(request.selector),
            )
            for request in self.requests
        )

        if self.section_found:
            self._apply_annotations(root)
            markdown_selector.keep_section_only()

        return root


# https://Markdown.github.io/extensions/api/
# https://stackoverflow.com/questions/29259912/how-can-i-get-a-list-of-image-urls-from-a-markdown-file-in-python
class _SelectorExtension(Extension):
    """Register the selector treeprocessor and expose its results."""

    def __init__(self, requests: tuple[SelectorRequest, ...]) -> None:
        super().__init__()
        self.requests = requests
        self.processor: _SelectorTreeprocessor | None = None

    def extendMarkdown(self, md: Markdown) -> None:  # ruff:ignore[invalid-function-name]
        self.processor = _SelectorTreeprocessor(md, self.requests)
        # Run last so the selectors see the final element structure.
        md.treeprocessors.register(self.processor, "csaf_selector", -1)


def _source_from_anchor(md_content: str, anchor: str) -> str | None:
    """Return source beginning at the line containing the configured HTML anchor.

    Returns ``None`` if the anchor is not present.
    """
    offset = 0
    for line in md_content.splitlines(keepends=True):
        if _parse_html_fragment(line, anchor)[1]:
            return md_content[offset:]
        offset += len(line)
    return None


def render_markdown_section(
    md_content: str,
    requests: Iterable[SelectorRequest] = (),
    anchor: str = SECTION_ANCHOR,
) -> RenderedSection:
    """Parse, resolve/highlight selectors, and return the target section HTML.

    If ``anchor`` is absent, the result contains empty HTML.
    """
    request_tuple = tuple(requests)
    # Find ID anchor on the unparsed markdown (as the ID is already in HTML)
    section_source = _source_from_anchor(md_content, anchor)
    if section_source is None:
        return RenderedSection(
            html="",
            section_found=False,
            selectors=tuple(ResolvedSelector(request.input_file, request.selector, None) for request in request_tuple),
        )

    extension = _SelectorExtension(request_tuple)
    md = Markdown(
        extensions=[*MARKDOWN_EXTENSIONS, _CommonMarkListBoundaryExtension(), extension],
        # tab_length=MARKDOWN_TAB_LENGTH,
    )
    rendered = md.convert(section_source)

    if extension.processor is None:
        msg = "selector treeprocessor was not registered"
        raise RuntimeError(msg)

    return RenderedSection(
        html=rendered,
        section_found=extension.processor.section_found,
        selectors=extension.processor.results,
    )


def build_html_document(
    body: str,
    title: str,
    additional_css: str = "",
    script: str | None = None,
) -> str:
    """Build a complete visualization document."""
    styles = "\n".join(part for part in (additional_css, COMMON_CSS) if part)
    script_element = f"\n<script>\n{script}\n</script>" if script is not None else ""
    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
{styles}
</style>
</head>
<body>
{body}{script_element}
</body>
</html>
"""


def write_html_document(
    output_file: Path,
    body: str,
    title: str,
    additional_css: str = "",
    script: str | None = None,
) -> None:
    """Build and write a visualization document."""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        build_html_document(
            body=body,
            title=title,
            additional_css=additional_css,
            script=script,
        ),
        encoding="utf-8",
    )


class Visualizer:
    """Generate an HTML visualization from revision and testcase data."""

    # Intended to later directly refer/link to the specific test
    TEST_REPO_INPUT_LOCATION = "https://github.com/csaf-testsuite/csaf-2.0-to-csaf-2.1/blob/main/input/"

    def __init__(self, revisions: dict[str, str], testcases_path: Path) -> None:
        """Load the visualizer configuration and testcase JSON.

        Raises:
            OSError: If the testcase file cannot be read.
            UnicodeError: If the testcase file is not valid UTF-8.
            json.JSONDecodeError: If the testcase file does not contain valid JSON.
        """
        self.revisions = revisions
        self.testcases = json.loads(testcases_path.read_text(encoding="utf-8"))

    def _testcase_revision(self) -> str:
        """Return the configured output CSAF revision.

        Raises:
            ValueError: If the testcase revision is missing or is not configured.
        """
        revision = self.testcases.get("output_csaf_revision")

        if revision is None:
            msg = "Test case revision output_csaf_revision not found in revisions."
            raise ValueError(msg)
        if revision not in self.revisions:
            msg = f"Test case revision '{revision}' not found in revisions."
            raise ValueError(msg)

        return revision

    def _selector_requests(self) -> tuple[SelectorRequest, ...]:
        """Return all selector requests from the testcase file."""
        return tuple(
            SelectorRequest(input_file=testcase["input"], selector=selector)
            for testcase in self.testcases.get("converter_tests", [])
            for selector in testcase.get("is_testing", [])
        )

    def visualize(
        self,
        output: Path = Path("output"),
        *,
        include_interactive_selector: bool = False,
    ) -> None:
        """Write a highlighted HTML visualization for the testcase revision.

        If ``include_interactive_selector`` is true, the document also embeds
        the interactive selector creator.

        No file is written if the target section is absent. The process exits
        with status 1 if revision content cannot be obtained.

        Raises:
            ValueError: If the testcase revision is missing or is not configured.
            OSError: If the output directory or HTML file cannot be written.
            SystemExit: If revision content cannot be obtained.
        """
        revision = self._testcase_revision()
        revision_content = get_revision_content(revision, self.revisions)
        if not revision_content:
            sys.exit(1)

        rendered = render_markdown_section(revision_content, self._selector_requests())
        if not rendered.section_found:
            logger.warning("Section with anchor '%s' not found in revision '%s'.", SECTION_ANCHOR, revision)
            return

        for resolved in rendered.selectors:
            if not resolved.is_resolved:
                logger.warning(
                    "Selector '%s' could not be resolved in revision '%s' for input file '%s'.",
                    json.dumps(resolved.selector, ensure_ascii=False),
                    revision,
                    resolved.input_file,
                )

        if include_interactive_selector:
            output_name = "marked_interactive_selector.html"
            title = "CSAF test case visualization and selector"
            script = SELECTOR_SCRIPT_PATH.read_text(encoding="utf-8")
        else:
            output_name = "marked.html"
            title = "CSAF test case visualization"
            script = None

        output_file = output / revision / output_name
        write_html_document(output_file, rendered.html, title, COVERAGE_CSS, script)
        logger.info("Visualization for revision '%s' written to '%s'.", revision, output_file)


def get_program_cache_dir() -> Path:
    """Create and return the temporary revision cache directory."""
    try:
        path = Path(tempfile.gettempdir()) / "csaf-visualizer"
        path.mkdir(parents=True, exist_ok=True)
        return path
    except OSError as error:
        logger.warning("Error occurred while creating cache directory: %s", error)
        return Path(tempfile.gettempdir())


def load_revisions(revisions: Mapping[str, str] | None = None) -> dict[str, str]:
    """Load revision Markdown from local paths or cached remote URLs.

    Remote revisions that return an HTTP error are logged and omitted from
    the returned mapping. Failure to write a downloaded revision to the
    cache does not omit that revision.

    Raises:
        ValueError: If a revision URI is neither a local file nor HTTP(S).
        OSError: If a local revision or existing cache file cannot be read.
        UnicodeError: If revision content is not valid UTF-8.
        urllib.error.URLError: If a remote revision cannot be reached.
    """
    cache_dir = get_program_cache_dir()
    return_revisions: dict[str, str] = {}

    if revisions is None:
        revisions = REVISIONS

    for revision, url in revisions.items():
        if not is_remote_url(url):
            local_file = Path(url)
            if local_file.exists():
                return_revisions[revision] = local_file.read_text(encoding="utf-8")
                continue

            msg = f"Revision URI '{url}' is neither a valid local file path nor a valid remote URL."
            raise ValueError(msg)

        url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()
        cache_file = cache_dir / f"{url_hash}.md"

        if not cache_file.exists():
            logger.info("Downloading %s...", url)
            try:
                with urllib.request.urlopen(url, timeout=15) as response:
                    content = response.read().decode("utf-8")
            except urllib.error.HTTPError as error:
                logger.error("Error occurred while trying to download %s: %s", url, error)
                continue

            return_revisions[revision] = content

            try:
                cache_file.write_text(content, encoding="utf-8")
            except OSError as error:
                # A failed cache write should not make an otherwise valid
                # remote revision unusable.
                logger.warning("Error occurred while writing to cache file: %s", error)
        else:
            try:
                return_revisions[revision] = cache_file.read_text(encoding="utf-8")
            except OSError as error:
                logger.warning("Error occurred while reading from cache file: %s", error)
                raise

    return return_revisions


def is_remote_url(value: str) -> bool:
    """Return whether ``value`` is an HTTP(S) URL."""
    parsed = urlparse(value)
    return parsed.scheme.lower() in {"http", "https"}


def get_revision_content(revision: str, revisions: dict[str, str]) -> str | None:
    """Return Markdown content for a configured revision or commit hash.

    Returns ``None`` if ``revision`` is invalid or a remote revision returns
    an HTTP error.

    Raises:
        ValueError: If the resolved revision URI is invalid.
        OSError: If a local revision or existing cache file cannot be read.
        UnicodeError: If revision content is not valid UTF-8.
        urllib.error.URLError: If a remote revision cannot be reached.
    """
    if revision in revisions:
        smaller_revisions = {revision: revisions[revision]}
    elif COMMIT_TAG_PATTERN.fullmatch(revision):
        smaller_revisions = {revision: REVISION_TEMPLATE.format(tag=revision)}
    else:
        logger.error("Revision %s is invalid.", revision)
        return None

    return load_revisions(smaller_revisions).get(revision)


def test_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Resolve a selector and print its matched text.

    Raises:
        OSError: If an input file cannot be read.
        UnicodeError: If an input file is not valid UTF-8.
        json.JSONDecodeError: If the testcase file does not contain valid JSON.
        ValueError: If the testcase revision is missing or is not configured.
        SystemExit: If required arguments are missing or mutually exclusive.
    """
    if args.file_option and args.file_positional:
        parser.error("Please provide either --file or the positional file argument, not both.")
    if args.selector_option and args.selector_positional:
        parser.error("Please provide either --selector or the positional selector argument, not both.")

    file_path = args.file_option or args.file_positional
    selector_json = args.selector_option or args.selector_positional

    if not selector_json:
        parser.error("A selector must be provided for the 'test' command.")

    try:
        selector = json.loads(selector_json)
    except json.JSONDecodeError as error:
        parser.error(f"Selector must be a valid JSON array: {error.msg}.")
    if not isinstance(selector, list):
        parser.error("Selector must be a JSON array.")

    if file_path:
        md_content = Path(file_path).read_text(encoding="utf-8")
        input_file = str(file_path)
    else:
        visualizer = Visualizer(args.revisions, Path(args.testcases))
        revision = visualizer._testcase_revision()
        md_content = get_revision_content(revision, args.revisions)
        if not md_content:
            sys.exit(1)
        input_file = revision

    rendered = render_markdown_section(
        md_content,
        [SelectorRequest(input_file=input_file, selector=selector)],
    )
    result = rendered.selectors[0]

    print(f"Selector: {json.dumps(selector, ensure_ascii=False)}")
    print(f"Result: {'resolved' if result.is_resolved else 'unresolved'}")
    if result.match is not None:
        print(result.match.text)


def visualize_command(
    args: argparse.Namespace,
    *,
    include_interactive_selector: bool = False,
) -> None:
    """Generate the highlighted testcase visualization.

    Raises:
        OSError: If an input or output file cannot be read or written.
        UnicodeError: If an input file is not valid UTF-8.
        json.JSONDecodeError: If the testcase file does not contain valid JSON.
        ValueError: If the testcase revision is missing or is not configured.
        SystemExit: If revision content cannot be obtained.
    """
    visualizer = Visualizer(args.revisions, Path(args.testcases))
    visualizer.visualize(
        output=Path(args.output),
        include_interactive_selector=include_interactive_selector,
    )


def interactive_selection_command(args: argparse.Namespace) -> None:
    """Generate the unannotated section plus the interactive selector script.

    No file is written if the target section is absent. The process exits with
    status 1 if revision content cannot be obtained.

    Raises:
        OSError: If the selector script or output file cannot be read or written.
        SystemExit: If revision content cannot be obtained.
    """
    revisions = args.revisions
    if revisions is None:
        revisions = REVISIONS

    revision_content = get_revision_content(args.revision, revisions)
    if not revision_content:
        sys.exit(1)

    rendered = render_markdown_section(revision_content)
    if not rendered.section_found:
        logger.warning("Section with anchor '%s' not found in revision '%s'.", SECTION_ANCHOR, args.revision)
        return

    output_file = Path(args.output) / args.revision / "interactive_selector.html"
    write_html_document(
        output_file,
        rendered.html,
        "CSAF test case selector",
        script=SELECTOR_SCRIPT_PATH.read_text(encoding="utf-8"),
    )
    logger.info("Visualization for revision '%s' written to '%s'.", args.revision, output_file)


def main() -> None:
    """Run the command-line interface."""
    def add_testcase_revision_arguments(parser: argparse.ArgumentParser) -> None:
        """Add arguments for resolving a revision from the testcase file."""
        parser.add_argument(
            "--revisions",
            type=json.loads,
            help="JSON dict to map revision key to local or remote Markdown file path or URL",
            required=False,
            default=json.dumps(REVISIONS),
        )
        parser.add_argument(
            "--testcases",
            type=str,
            help="Path to the JSON file containing test cases",
            default="converter-testcases-20-21.json",
        )

    def add_testcase_visualization_arguments(parser: argparse.ArgumentParser) -> None:
        """Add arguments shared by testcase-driven visualization commands."""
        add_testcase_revision_arguments(parser)
        parser.add_argument("--output", type=str, help="Path to the output directory", default="output")

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Visualizer")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    test_parser = subparsers.add_parser("test", help="Test a selector against a Markdown revision")
    test_parser.add_argument(
        "file_positional",
        nargs="?",
        help="Path to the Markdown file to test against; defaults to the testcase revision",
    )
    test_parser.add_argument("selector_positional", nargs="?", help="Selector JSON array to test")
    test_parser.add_argument(
        "--file",
        dest="file_option",
        help="Path to the Markdown file to test against; defaults to the testcase revision",
    )
    test_parser.add_argument(
        "--selector",
        "--locator",
        dest="selector_option",
        help="Selector JSON array to test",
    )
    add_testcase_revision_arguments(test_parser)

    visualize_parser = subparsers.add_parser("visualize", help="Visualize selectors")
    add_testcase_visualization_arguments(visualize_parser)

    interactive_visualization_parser = subparsers.add_parser(
        "interactive-visualization",
        help="Visualize selectors and enable interactive selector creation",
    )
    add_testcase_visualization_arguments(interactive_visualization_parser)

    interactive_selection_parser = subparsers.add_parser(
        "interactive-selection",
        help="Create an HTML file with an interactive location selector",
    )
    interactive_selection_parser.add_argument(
        "--revisions",
        type=json.loads,
        help="JSON dict to map revision key to local or remote Markdown file path or URL",
        required=False,
        default=json.dumps(REVISIONS),
    )
    interactive_selection_parser.add_argument(
        "--revision",
        type=str,
        help="ID of revision to generate HTML for",
        required=False,
        default="2.1-csd03",
    )
    interactive_selection_parser.add_argument(
        "--output",
        type=str,
        help="Path to the output directory",
        default="output",
    )

    test_parser.set_defaults(handler=partial(test_command, parser=parser))
    visualize_parser.set_defaults(handler=visualize_command)
    interactive_visualization_parser.set_defaults(
        handler=partial(visualize_command, include_interactive_selector=True)
    )
    interactive_selection_parser.set_defaults(handler=interactive_selection_command)

    args = parser.parse_args()
    if hasattr(args, "handler"):
        args.handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
