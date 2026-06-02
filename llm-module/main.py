"""
Entry point for running secure coding experiments.

This script:
- initializes the evaluator
- configures experiment parameters
- runs the full pipeline (train + test)

Modify `training_overrides` to run different experiments.
"""

from experiment import run_experiment
from evaluator import Evaluator
from pathlib import Path

if __name__ == "__main__":
    BASE_DIR = Path(__file__).resolve().parent

    # Path to dataset enriched metadata root
    metadata_root = (
        BASE_DIR.parent /
        "secure-assist" /
        "enriched"
    )

    # Evaluator instance (defines scoring logic)
    evaluator = Evaluator()

    # Run experiment with optional config overrides
    run_experiment(
        metadata_root=metadata_root,

        # Name used for checkpoint directory:
        # ./checkpoints/<experiment_name>
        experiment_name="stage1-qwen",

        # Override default training configuration
        training_overrides={
            "learning_rate": 2e-4,
            "lora_rank": 16,
            "epochs": 3,
        },

        evaluator=evaluator,
    )
