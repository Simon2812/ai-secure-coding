/**
 * Whitespace-tolerant matching of a model's `origin` snippet against source.
 *
 * The model frequently returns the snippet with its own formatting — most often
 * with the indentation of continuation lines dropped — so an exact string search
 * misses. Both texts are normalized (runs of whitespace collapsed to a single
 * space) and every normalized character keeps a span back into the original, so
 * a match can be translated to a real range in the untouched source.
 *
 * Ported from the CLI's `_build_normalized_text` / `_find_normalized_spans`
 * (cli/asc/../evaluator.py) so both agree on what "the same snippet" means.
 */

interface NormalizedText {
  normalized: string;
  /** For each normalized character, [startIndex, endIndex) in the original. */
  spans: Array<[number, number]>;
}

function buildNormalizedText(text: string): NormalizedText {
  const parts: string[] = [];
  const spans: Array<[number, number]> = [];
  let previousWasSpace = false;
  let i = 0;

  while (i < text.length) {
    const char = text[i];

    // Literal escape sequences: the model sometimes emits "\n" as two
    // characters rather than a newline.
    if (char === "\\" && i + 1 < text.length) {
      const next = text[i + 1];
      if (next === "n" || next === "r" || next === "t") {
        if (!previousWasSpace) {
          parts.push(" ");
          spans.push([i, i + 2]);
          previousWasSpace = true;
        }
        i += 2;
        continue;
      }
      if (next === '"' || next === "'" || next === "\\") {
        parts.push(next);
        spans.push([i, i + 2]);
        previousWasSpace = false;
        i += 2;
        continue;
      }
    }

    if (/\s/.test(char)) {
      if (!previousWasSpace) {
        parts.push(" ");
        spans.push([i, i + 1]);
        previousWasSpace = true;
      }
      i += 1;
      continue;
    }

    parts.push(char);
    spans.push([i, i + 1]);
    previousWasSpace = false;
    i += 1;
  }

  return collapseSpacesAroundPunctuation({ normalized: parts.join(""), spans });
}

/** Identifier characters — a space between two of these is significant. */
const WORD = /[A-Za-z0-9_$]/;

/**
 * Drop spaces that sit next to punctuation.
 *
 * Collapsing whitespace runs to a single space is not enough on its own,
 * because the model reflows wrapped statements. Where the file has
 *
 *     return statement.executeUpdate(
 *             "UPDATE invoices SET ..." + id);
 *
 * the model returns it on one line, so the file normalizes to
 * `executeUpdate( "UPDATE` and the model to `executeUpdate("UPDATE` — one
 * space against none, and the match fails on code that is plainly the same.
 *
 * A space is only meaningful when it separates two identifier characters
 * (`else if`, `int x`). Next to a bracket, operator, comma or quote it carries
 * no meaning in any of the three languages, so it is removed from both sides
 * of the comparison.
 */
function collapseSpacesAroundPunctuation(text: NormalizedText): NormalizedText {
  const chars = text.normalized;
  const parts: string[] = [];
  const spans: Array<[number, number]> = [];

  for (let i = 0; i < chars.length; i++) {
    if (chars[i] === " ") {
      const before = parts.length ? parts[parts.length - 1] : "";
      const after = chars[i + 1] ?? "";
      // Keep it only when it genuinely separates two identifiers.
      if (!(WORD.test(before) && WORD.test(after))) continue;
    }
    parts.push(chars[i]);
    spans.push(text.spans[i]);
  }

  return { normalized: parts.join(""), spans };
}

/**
 * Locate `origin` in `code`, ignoring differences in whitespace.
 * Returns character offsets into the original `code`, or undefined if absent.
 */
export function findOriginRange(
  code: string,
  origin: string
): { start: number; end: number } | undefined {
  const target = buildNormalizedText(origin).normalized.trim();
  if (!target) return undefined;

  const source = buildNormalizedText(code);
  const index = source.normalized.indexOf(target);
  if (index < 0) return undefined;

  const lastIndex = index + target.length - 1;
  if (lastIndex >= source.spans.length) return undefined;

  return { start: source.spans[index][0], end: source.spans[lastIndex][1] };
}

/** True when `origin` appears in `code`, ignoring whitespace differences. */
export function containsOrigin(code: string, origin: string): boolean {
  return findOriginRange(code, origin) !== undefined;
}

/** 1-based line number of a character offset. */
function lineOf(code: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < code.length; i++) {
    if (code[i] === "\n") line++;
  }
  return line;
}

interface Locatable {
  cwe: string;
  fixes?: { origin: string; replacement: string }[];
  start_line?: number;
  end_line?: number;
}

/**
 * Tie model findings back to real positions in the file, discarding any that
 * cannot be placed.
 *
 * The model sometimes returns a fix for code that is not in the file at all —
 * a remembered pattern rather than something it read. Such a finding has no
 * location, cannot be shown in context, verified or applied, so it is dropped
 * rather than surfaced as an unactionable entry.
 *
 * Where the server failed to supply a line but the origin *is* present, the
 * range is recovered here using whitespace-tolerant matching.
 */
export function groundVulnerabilities<T extends Locatable>(
  vulns: T[],
  code: string
): { grounded: T[]; discarded: T[] } {
  const grounded: T[] = [];
  const discarded: T[] = [];

  for (const vuln of vulns) {
    if (vuln.start_line != null) {
      grounded.push(vuln);
      continue;
    }

    // No line from the server — try to derive one from a fix we can locate.
    let located: T | undefined;
    for (const fix of vuln.fixes ?? []) {
      const range = findOriginRange(code, fix.origin);
      if (!range) continue;
      located = {
        ...vuln,
        start_line: lineOf(code, range.start),
        end_line: lineOf(code, Math.max(range.start, range.end - 1)),
      };
      break;
    }

    if (located) grounded.push(located);
    else discarded.push(vuln);
  }

  return { grounded, discarded };
}
