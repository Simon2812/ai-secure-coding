from pathlib import Path
import gc
import json
import torch
from model import SecureCodingModel


def run_experiment(
    metadata_root,
    experiment_name,
    evaluator,
    training_overrides=None,
):
    """
    Run full pipeline:
    - load model
    - load dataset
    - train
    - test

    Saves everything under checkpoints/<experiment_name>.
    """

    model = SecureCodingModel()

    # -------- Apply overrides --------
    if training_overrides:
        model.training_config.update(training_overrides)

    print("\n===== EXPERIMENT CONFIG =====")
    for k, v in model.training_config.items():
        print(f"{k}: {v}")

    # -------- Define checkpoint path --------
    checkpoint_path = Path("./checkpoints") / experiment_name

    if checkpoint_path.exists():
        print("WARNING: Overwriting existing checkpoint")

    checkpoint_path.mkdir(parents=True, exist_ok=True)

    # -------- Load model --------
    model.load_model()

    # -------- Load dataset --------
    train_data, val_data, test_data = model.load_dataset(metadata_root)

    # -------- Train --------
    model.train(
        train_data,
        val_data,
        evaluator,
        checkpoint_path,
    )

    # -------- Free training model before loading best checkpoint --------
    model.model = None
    gc.collect()

    if torch.cuda.is_available():
        torch.cuda.empty_cache()

    # -------- Load best checkpoint --------
    model.load_checkpoint(checkpoint_path / "best")

    # -------- Test --------
    test_results = model.test(test_data, evaluator)

    # -------- Save results --------
    with open(checkpoint_path / "test_results.json", "w") as f:
        json.dump(test_results, f, indent=4)

    with open(checkpoint_path / "training_config.json", "w") as f:
        json.dump(model.training_config, f, indent=4)

    print(f"\nExperiment saved to: {checkpoint_path}")

    return test_results
