from collections import defaultdict

def metric_dict():
    """
    Create empty metric structure.
    """
    return {
        "final": [],
        "cwe": [],
        "fix": [],
    }


def pr_dict():
    """
    Create empty precision/recall counter structure.
    """

    return {
        "tp": 0,
        "fp": 0,
        "fn": 0,
    }


def update_pr_counts(stats, gt_cwes, pred_cwes):
    """
    Update micro precision/recall counts
    for a set of ground-truth and predicted CWEs.
    """

    stats["tp"] += len(gt_cwes & pred_cwes)
    stats["fp"] += len(pred_cwes - gt_cwes)
    stats["fn"] += len(gt_cwes - pred_cwes)


def update_per_cwe_pr_counts(stats_dict, gt_cwes, pred_cwes):
    """
    Update per-CWE precision/recall counts.

    False positives are counted under the predicted CWE.
    False negatives are counted under the missed ground-truth CWE.
    """

    for cwe in gt_cwes | pred_cwes:
        if cwe in gt_cwes and cwe in pred_cwes:
            stats_dict[cwe]["tp"] += 1
        elif cwe in pred_cwes:
            stats_dict[cwe]["fp"] += 1
        else:
            stats_dict[cwe]["fn"] += 1


def precision_recall(stats):
    """
    Compute precision and recall from TP/FP/FN counts.
    """

    tp = stats["tp"]
    fp = stats["fp"]
    fn = stats["fn"]

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

    return precision, recall


def print_group_stats(title, stats_dict):
    """
    Print averaged metrics per group (CWE, language, etc.).
    """

    print(f"\n{title}")

    for key in sorted(stats_dict):
        data = stats_dict[key]

        # Safety against empty lists
        if len(data["final"]) == 0:
            continue

        final_avg = sum(data["final"]) / len(data["final"])
        cwe_avg = sum(data["cwe"]) / len(data["cwe"])
        fix_avg = sum(data["fix"]) / len(data["fix"])

        print(
            f"{key} | "
            f"Final: {final_avg:.4f} | "
            f"CWE: {cwe_avg:.4f} | "
            f"Fix: {fix_avg:.4f}"
        )


def print_pr_stats(title, stats_dict):
    """
    Print precision/recall counts per group.
    """

    print(f"\n{title}")

    for key in sorted(stats_dict):
        data = stats_dict[key]
        precision, recall = precision_recall(data)

        print(
            f"{key} | "
            f"Precision: {precision:.4f} | "
            f"Recall: {recall:.4f} | "
            f"TP: {data['tp']} | "
            f"FP: {data['fp']} | "
            f"FN: {data['fn']}"
        )
