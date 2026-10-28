/**
 * Script that shows the a selector when clicking on a bullet point or when doing a selection.
 *
 * Currently this can be pasted into the browser console on
 * https://docs.oasis-open.org/csaf/csaf/v2.1/csaf-v2.1.html#conformance-clause-18-csaf-2-0-to-csaf-2-1-converter
 * and then works in section 9.1.18 (any behavior outside of that section is unintentional).
 *
 * This is just temporary. In the future, the script is intended to be embedded into an HTML file.
 *
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
 * Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
 */
const ORDINALS = [
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
];

function normalizeLocatorText(text) {
  return text.replace(/\s+/g, " ").replace(/[“”]/g, '"').trim();
}

function getListItems(list) {
  return Array.from(list.children).filter((child) => child.tagName === "LI");
}

function getItemNumber(li, list) {
  const items = getListItems(list);
  const index = items.indexOf(li);

  if (index === -1) {
    return null;
  }

  return index + 1;
}

function formatListMarker(li, list) {
  const number = getItemNumber(li, list);
  // https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/Properties/list-style-type
  const style = getComputedStyle(li).listStyleType;

  switch (style) {
    case "disc":
      return `•${number}`;

    case "circle":
      return `◦${number}`;

    case "square":
      return `▪${number}`;

    case "decimal":
      return `${number}.`;

    case "lower-alpha":
    case "lower-latin":
      return `${String.fromCharCode(97 + ((number - 1) % 26))}.`;

    default:
      return list.tagName === "OL" ? `${number}.` : `•${number}`;
  }
}

function getListPath(li) {
  const path = [];

  let currentLi = li;

  let prevSilbing = null;
  while (currentLi) {
    const list = currentLi.parentElement;

    if (!list || !list.matches("ul, ol")) {
      break;
    }

    path.unshift(formatListMarker(currentLi, list));

    prevSilbing = list.previousElementSibling;
    currentLi = list.parentElement?.closest("li") ?? null;
  }

  if (prevSilbing) {
    path.unshift(ORDINALS.find((item) => prevSilbing.innerText.includes(item)));
  }

  return path.join(" ");
}

document.querySelectorAll("li").forEach((li) => {
  // Normal click
  li.addEventListener("click", (event) => {
    // Don't also fire the click path when the click finished a text selection.
    const selection = window.getSelection();

    if (selection && !selection.isCollapsed) {
      return;
    }

    event.stopPropagation();

    highlightListItem(li);

    const selectorObj = JSON.stringify([getListPath(li)]);

    setLocator(selectorObj);
  });

  // Text selection inside a UL/OL
  li.addEventListener("mouseup", () => {
    const selection = window.getSelection();
    const selectedText = normalizeLocatorText(selection?.toString() ?? "");

    if (!selectedText || !selection?.rangeCount) {
      return;
    }

    const selectedRange = selection.getRangeAt(0);

    if (!li.contains(selectedRange.commonAncestorContainer)) {
      return;
    }

    event.stopPropagation();

    highlightRange(selectedRange);

    const occurrence = getTextOccurrence(li, selectedText, selectedRange);

    const selectorObj = JSON.stringify([
      getListPath(li),
      [selectedText, occurrence ?? 1],
    ]);

    setLocator(selectorObj);
  });
});

function getNormalizedTextWithPositions(root) {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);

  // Each normalized character points back to its DOM position.
  const chars = [];
  let normalized = "";

  let node;

  while ((node = walker.nextNode())) {
    const text = node.nodeValue;

    for (let offset = 0; offset < text.length; offset++) {
      const char = text[offset];

      // Collapse all whitespace runs to one space.
      if (/\s/.test(char)) {
        if (
          normalized.length === 0 ||
          normalized[normalized.length - 1] === " "
        ) {
          continue;
        }

        normalized += " ";
        chars.push({
          node,
          startOffset: offset,
          endOffset: offset + 1,
        });
      } else {
        normalized += char;
        chars.push({
          node,
          startOffset: offset,
          endOffset: offset + 1,
        });
      }
    }
  }

  return { normalized, chars };
}

function findAllTextMatches(root, selectedText) {
  const { normalized, chars } = getNormalizedTextWithPositions(root);

  const needle = normalizeLocatorText(selectedText);

  if (!needle) {
    return [];
  }

  const matches = [];
  let searchFrom = 0;

  while (true) {
    const index = normalized.indexOf(needle, searchFrom);

    if (index === -1) {
      break;
    }

    const first = chars[index];
    const last = chars[index + needle.length - 1];

    const range = document.createRange();

    range.setStart(first.node, first.startOffset);
    range.setEnd(last.node, last.endOffset);

    matches.push(range);

    searchFrom = index + needle.length;
  }

  return matches;
}

// Text selection outside of list items, e.g. in a table below a list.
document.addEventListener("mouseup", () => {
  const selection = window.getSelection();
  const selectedText = normalizeLocatorText(selection?.toString() ?? "");

  if (!selectedText || !selection?.rangeCount) {
    return;
  }

  const selectedRange = selection.getRangeAt(0);
  const node = selectedRange.commonAncestorContainer;
  const ordinalOf = (p) =>
    ORDINALS.find((item) => p.textContent.trim().startsWith(`${item},`));
  const ordinalParagraphs = [...document.querySelectorAll("p")].filter(
    ordinalOf,
  );
  const start = ordinalParagraphs.findLast(
    (p) => p.compareDocumentPosition(node) & Node.DOCUMENT_POSITION_FOLLOWING,
  );

  const blocks = [];
  for (
    let block = start?.nextElementSibling;
    block && !ordinalParagraphs.includes(block);
    block = block.nextElementSibling
  ) {
    blocks.push(block);
  }

  if (!blocks.some((block) => block.contains(node))) {
    return;
  }

  const index = blocks
    .flatMap((block) => findAllTextMatches(block, selectedText))
    .findIndex((range) => rangesEqual(range, selectedRange));

  highlightRange(selectedRange);
  setLocator(
    JSON.stringify([ordinalOf(start), [selectedText, index + 1 || 1]]),
  );
});

function findTextRange(root, selectedText, occurrence = 1) {
  const matches = findAllTextMatches(root, selectedText);

  return matches[occurrence - 1] ?? null;
}

function rangesEqual(a, b) {
  return (
    a.startContainer === b.startContainer &&
    a.startOffset === b.startOffset &&
    a.endContainer === b.endContainer &&
    a.endOffset === b.endOffset
  );
}

function getTextOccurrence(root, selectedText, selectedRange) {
  const matches = findAllTextMatches(root, selectedText);

  if (matches.length <= 1) {
    return null;
  }

  const index = matches.findIndex((range) => rangesEqual(range, selectedRange));

  return index === -1 ? null : index + 1;
}

// Top bar
const locatorBar = document.createElement("div");
const locatorInput = document.createElement("input");
const copyButton = document.createElement("button");

locatorInput.type = "text";
locatorInput.readOnly = "true";
copyButton.textContent = "Copy";
copyButton.type = "button";

locatorBar.append(locatorInput, copyButton);

Object.assign(locatorBar.style, {
  position: "sticky",
  top: "0",
  zIndex: "9999",
  background: "white",
  display: "flex",
  padding: "4px 1px",
  fontSize: "medium",
});

Object.assign(locatorInput.style, {
  flex: "1",
  width: "100%",
  fontSize: "inherit",
});

Object.assign(copyButton.style, {
  fontSize: "inherit",
});

locatorBar.append(locatorInput, copyButton);
document.body.prepend(locatorBar);

let currentLocator = "";

function setLocator(locator) {
  currentLocator = locator;
  locatorInput.value = locator;
}

copyButton.addEventListener("click", async (event) => {
  event.stopPropagation();

  if (!currentLocator) {
    return;
  }

  await navigator.clipboard.writeText(currentLocator);

  const oldText = copyButton.textContent;
  copyButton.textContent = "Copied";

  setTimeout(() => {
    copyButton.textContent = oldText;
  }, 1000);
});

// Selection highlight overlay
const highlightLayer = document.createElement("div");

Object.assign(highlightLayer.style, {
  position: "fixed",
  inset: "0",
  zIndex: "9998",
  pointerEvents: "none",
});

document.body.append(highlightLayer);

let currentHighlight = null;
let highlightUpdatePending = false;

function clearHighlight() {
  currentHighlight = null;
  highlightLayer.replaceChildren();
}

function createHighlightBox(rect) {
  if (rect.width <= 0 || rect.height <= 0) {
    return;
  }

  const box = document.createElement("div");

  Object.assign(box.style, {
    position: "fixed",
    left: `${rect.left - 2}px`,
    top: `${rect.top - 2}px`,
    width: `${rect.width + 4}px`,
    height: `${rect.height + 4}px`,
    boxSizing: "border-box",
    border: "2px solid #1976d2",
    borderRadius: "3px",
    pointerEvents: "none",
  });

  highlightLayer.append(box);
}

function renderHighlight() {
  highlightLayer.replaceChildren();

  if (!currentHighlight) {
    return;
  }

  if (currentHighlight.type === "range") {
    createHighlightBox(currentHighlight.range.getBoundingClientRect());
    return;
  }

  if (currentHighlight.type === "list-item") {
    createHighlightBox(currentHighlight.element.getBoundingClientRect());
  }
}

function scheduleHighlightUpdate() {
  if (highlightUpdatePending) {
    return;
  }

  highlightUpdatePending = true;

  requestAnimationFrame(() => {
    highlightUpdatePending = false;
    renderHighlight();
  });
}

function highlightRange(range) {
  currentHighlight = {
    type: "range",
    range: range.cloneRange(),
  };

  renderHighlight();
}

function highlightListItem(li) {
  currentHighlight = {
    type: "list-item",
    element: li,
  };

  renderHighlight();
}

// Keep the box attached while the viewport moves.
window.addEventListener("scroll", scheduleHighlightUpdate, {
  passive: true,
  capture: true,
});

window.addEventListener("resize", scheduleHighlightUpdate);
