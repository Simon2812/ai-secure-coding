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
