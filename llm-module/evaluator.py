import json
import subprocess
import tempfile
from difflib import SequenceMatcher

from pathlib import Path
from collections import Counter


class Evaluator:
    """
    Secure coding evaluator.

    Responsibilities:
    - compare predicted and ground-truth CWEs
    - apply predicted fixes
    - validate fixes through analyzer reruns
    - compute final evaluation scores

    Note:
    - compilation is intentionally not used for scoring.
    """

    def __init__(self):
        """
        Initialize evaluator paths
        and language configuration.
        """

        # Assumes repository layout:
        # repo/
        # ├── secure-assist/
        # └── llm-module/
        self.project_root = (
            Path(__file__).resolve().parent.parent
            / "secure-assist"
        ).resolve()

        self.analyzer_runner = (
            self.project_root
            / "src"
            / "analyzer"
            / "analyzer_runner.ts"
        )

        if not self.analyzer_runner.exists():
            raise RuntimeError(
                f"Analyzer runner not found: {self.analyzer_runner}"
            )

        self.language_suffix = {
            "c": ".c",
            "cpp": ".cpp",
            "python": ".py",
            "java": ".java",
        }

    def evaluate(self, sample, prediction):
        """
        Evaluate a single prediction.

        Scoring:
        - cwe_score compares predicted CWE IDs with ground truth CWE IDs.
        - fix_score measures whether analyzer findings for ground-truth CWEs
          are reduced after applying predicted fixes.
        - final_score is the average of cwe_score and fix_score.

        Returns:
            dict with keys:
                - final_score
                - cwe_score
                - fix_score
        """

        pred_vulns = self._get_predicted_vulns(
            prediction
        )

        gt_cwes = set(
            sample["cwes"]
        )

        pred_cwes = self._extract_predicted_cwes(
            pred_vulns
        )

        cwe_score = self._f1_score(
            gt_cwes,
            pred_cwes,
        )

        # Safe sample case.
        if not gt_cwes:
            fix_score = (
                1.0
                if not pred_cwes
                else 0.0
            )

            return {
                "final_score": (
                    0.5 * cwe_score +
                    0.5 * fix_score
                ),
                "cwe_score": cwe_score,
                "fix_score": fix_score,
            }

        patched_code = self._apply_fixes(
            code=sample["code"],
            pred_vulns=pred_vulns,
            gt_cwes=gt_cwes,
        )

        analyzer_score, introduced_findings = (
            self._analyze_reduction(
                patched_code=patched_code,
                sample=sample,
            )
        )

        introduced_penalty = min(
            0.8,
            0.05 * introduced_findings,
        )

        # Compilation is intentionally ignored.
        # Fix quality is measured only by analyzer finding reduction,
        # with a penalty for newly introduced findings.
        fix_score = (
            analyzer_score -
            introduced_penalty
        )

        fix_score = max(
            0.0,
            min(1.0, fix_score),
        )

        final_score = (
            0.5 * cwe_score +
            0.5 * fix_score
        )

        return {
            "final_score": final_score,
            "cwe_score": cwe_score,
            "fix_score": fix_score,
        }

    def _get_predicted_vulns(self, prediction):
        """
        Safely extract vulnerability list
        from model prediction.
        """

        if not isinstance(prediction, dict):
            return []

        pred_vulns = prediction.get(
            "vulnerabilities",
            [],
        )

        if not isinstance(pred_vulns, list):
            return []

        return pred_vulns

    def _extract_predicted_cwes(self, pred_vulns):
        """
        Extract CWE IDs from prediction.
        """

        return {
            vuln.get("cwe")
            for vuln in pred_vulns
            if isinstance(vuln, dict)
            and isinstance(vuln.get("cwe"), str)
        }

    def _f1_score(self, gt_cwes, pred_cwes):
        """
        Compute F1 score between
        ground-truth and predicted CWEs.
        """

        if not gt_cwes and not pred_cwes:
            return 1.0

        if not gt_cwes or not pred_cwes:
            return 0.0

        tp = len(
            gt_cwes &
            pred_cwes
        )

        fp = len(
            pred_cwes -
            gt_cwes
        )

        fn = len(
            gt_cwes -
            pred_cwes
        )

        precision = (
            tp / (tp + fp)
            if (tp + fp) > 0
            else 0.0
        )

        recall = (
            tp / (tp + fn)
            if (tp + fn) > 0
            else 0.0
        )

        if precision + recall == 0:
            return 0.0

        return (
            2 *
            precision *
            recall /
            (precision + recall)
        )

    def _normalize_for_match(self, text):
        """
        Normalize text for matching while preserving token content.

        Handles:
        - real whitespace/newlines
        - literal escape sequences like \\n, \\t, \\r
        - escaped quotes like \\" and \\\'
        - doubled backslashes
        """

        if not isinstance(text, str):
            return ""

        normalized, _ = self._build_normalized_text(text)
        return normalized


    def _build_normalized_text(self, text):
        """
        Build normalized text and map each normalized character
        back to a span in the original text.
        """

        normalized_parts = []
        span_map = []
        previous_was_space = False
        i = 0

        while i < len(text):
            char = text[i]

            if char == "\\" and i + 1 < len(text):
                next_char = text[i + 1]

                if next_char in {"n", "r", "t"}:
                    if not previous_was_space:
                        normalized_parts.append(" ")
                        span_map.append((i, i + 2))
                        previous_was_space = True
                    i += 2
                    continue

                if next_char in {'"', "'", "\\"}:
                    normalized_parts.append(next_char)
                    span_map.append((i, i + 2))
                    previous_was_space = False
                    i += 2
                    continue

            if char.isspace():
                if not previous_was_space:
                    normalized_parts.append(" ")
                    span_map.append((i, i + 1))
                    previous_was_space = True
                i += 1
                continue

            normalized_parts.append(char)
            span_map.append((i, i + 1))
            previous_was_space = False
            i += 1

        leading_trim = 0
        while (
            leading_trim < len(normalized_parts)
            and normalized_parts[leading_trim] == " "
        ):
            leading_trim += 1

        trailing_trim = len(normalized_parts)
        while (
            trailing_trim > leading_trim
            and normalized_parts[trailing_trim - 1] == " "
        ):
            trailing_trim -= 1

        normalized = "".join(
            normalized_parts[leading_trim:trailing_trim]
        )
        trimmed_map = span_map[leading_trim:trailing_trim]

        return normalized, trimmed_map


    def _find_fuzzy_normalized_span(
        self,
        normalized_code,
        span_map,
        normalized_origin,
    ):
        """
        Fuzzy fallback for small origin mismatches.
        Uses edit similarity over similarly sized windows.
        """

        origin_length = len(normalized_origin)

        if origin_length < 20:
            return None

        best_score = 0.0
        best_range = None
        min_window = max(1, int(origin_length * 0.80))
        max_window = min(
            len(normalized_code),
            int(origin_length * 1.20) + 1,
        )

        for window_length in range(min_window, max_window + 1):
            step = max(1, window_length // 8)

            for start in range(
                0,
                len(normalized_code) - window_length + 1,
                step,
            ):
                candidate = normalized_code[
                    start:start + window_length
                ]
                score = SequenceMatcher(
                    None,
                    normalized_origin,
                    candidate,
                    autojunk=False,
                ).ratio()

                if score > best_score:
                    best_score = score
                    best_range = (start, start + window_length)

        if best_score < 0.90 or best_range is None:
            return None

        start, end = best_range
        original_start = span_map[start][0]
        original_end = span_map[end - 1][1]

        return original_start, original_end


    def _find_normalized_span(self, code, origin):
        """
        Find origin in code while ignoring whitespace, common
        escape-sequence differences, and small model drift.

        Returns:
            (start, end) in original code, or None.
        """

        normalized_origin = self._normalize_for_match(origin)

        if not normalized_origin:
            return None

        normalized_code, span_map = self._build_normalized_text(code)

        if not normalized_code or not span_map:
            return None

        match_start = normalized_code.find(normalized_origin)

        if match_start != -1:
            match_end = match_start + len(normalized_origin)
            original_start = span_map[match_start][0]
            original_end = span_map[match_end - 1][1]
            return original_start, original_end

        return self._find_fuzzy_normalized_span(
            normalized_code,
            span_map,
            normalized_origin,
        )


    def find_origin_line_range(self, code, origin):
        """
        Return 1-based start/end lines for an origin snippet.
        """

        span = self._find_normalized_span(code, origin)

        if span is None:
            return None

        start, end = span
        start_line = code.count("\n", 0, start) + 1
        end_line = code.count("\n", 0, max(start, end - 1)) + 1

        return start_line, end_line

    def _apply_fixes(
        self,
        code,
        pred_vulns,
        gt_cwes,
    ):
        """
        Apply predicted fixes to source code.

        Only fixes associated with
        ground-truth CWEs are applied.
        """

        patched_code = code

        for vuln in pred_vulns:
            if not isinstance(vuln, dict):
                continue

            cwe = vuln.get("cwe")

            if cwe not in gt_cwes:
                continue

            fixes = vuln.get(
                "fixes",
                [],
            )

            if not isinstance(fixes, list):
                continue

            for fix in fixes:
                if not isinstance(fix, dict):
                    continue

                origin = fix.get("origin")
                replacement = fix.get("replacement")

                if not isinstance(origin, str):
                    continue

                if not isinstance(replacement, str):
                    continue

                if origin in patched_code:
                    patched_code = patched_code.replace(
                        origin,
                        replacement,
                        1,
                    )
                    continue
                
                span = self._find_normalized_span(
                    patched_code,
                    origin,
                )
                
                if span is not None:
                    start, end = span
                    patched_code = (
                        patched_code[:start] +
                        replacement +
                        patched_code[end:]
                    )

        return patched_code

    def _analyze_reduction(
        self,
        patched_code,
        sample,
    ):
        """
        Run analyzer on patched code and measure
        reduction of supported CWE findings.

        Returns:
            (
                analyzer_score,
                introduced_findings,
            )
        """

        gt_cwes = set(
            sample["cwes"]
        )

        original_findings = sample.get(
            "static_findings",
            [],
        )

        supported_original_counts = Counter()

        for finding in original_findings:
            if not isinstance(finding, dict):
                continue

            cwe = finding.get("cweId")

            if cwe in gt_cwes:
                supported_original_counts[cwe] += 1

        original_total = sum(
            supported_original_counts.values()
        )

        if original_total == 0:
            return 0.0, 0

        new_findings = self._run_analyzer(
            code=patched_code,
            language=sample["language"],
        )

        new_supported_total = 0

        for finding in new_findings:
            if not isinstance(finding, dict):
                continue

            cwe = finding.get("cweId")

            if cwe in supported_original_counts:
                new_supported_total += 1

        removed = max(
            0,
            original_total - new_supported_total,
        )

        analyzer_score = (
            removed /
            original_total
        )

        introduced_findings = self._count_introduced_findings(
            original_findings=original_findings,
            new_findings=new_findings,
        )

        return analyzer_score, introduced_findings

    def _count_introduced_findings(
        self,
        original_findings,
        new_findings,
    ):
        """
        Count findings introduced after patching.

        Counting is based on CWE frequency,
        not exact line numbers, because line
        numbers may change after fixes.
        """

        original_counts = self._count_findings_by_cwe(
            original_findings
        )

        new_counts = self._count_findings_by_cwe(
            new_findings
        )

        introduced = 0

        for cwe, new_count in new_counts.items():
            old_count = original_counts.get(
                cwe,
                0,
            )

            if new_count > old_count:
                introduced += (
                    new_count -
                    old_count
                )

        return introduced

    def _count_findings_by_cwe(self, findings):
        """
        Count analyzer findings by CWE ID.
        """

        counts = Counter()

        for finding in findings:
            if not isinstance(finding, dict):
                continue

            cwe = finding.get("cweId")

            if isinstance(cwe, str):
                counts[cwe] += 1

        return counts

    def _run_analyzer(self, code, language):
        """
        Run TypeScript analyzer through
        analyzer_runner.ts.
        """

        suffix = self.language_suffix.get(
            language
        )

        if suffix is None:
            raise RuntimeError(
                f"Unsupported language for analyzer: {language}"
            )

        with tempfile.TemporaryDirectory() as tmp:
            source_file = Path(tmp) / f"patched{suffix}"

            source_file.write_text(
                code,
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    "npx",
                    "ts-node",
                    str(self.analyzer_runner),
                    str(source_file),
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=20,
            )

            if result.returncode != 0:
                raise RuntimeError(
                    "Analyzer execution failed.\n"
                    f"STDOUT:\n{result.stdout}\n"
                    f"STDERR:\n{result.stderr}"
                )

            try:
                findings = json.loads(
                    result.stdout
                )

            except json.JSONDecodeError as error:
                raise RuntimeError(
                    "Analyzer returned invalid JSON.\n"
                    f"Output:\n{result.stdout}"
                ) from error

            if not isinstance(findings, list):
                raise RuntimeError(
                    "Analyzer output must be a JSON list."
                )

            return findings
