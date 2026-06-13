from pathlib import Path
import inspect
import json
import shutil

from huggingface_hub import snapshot_download
from peft import LoraConfig

from evaluator import Evaluator
from model import SecureCodingModel


HF_CHECKPOINT = "Simon2812/secure-coding-model"
EXPERIMENT_NAME = "hf-latest-test"


def patch_adapter_config(source_dir, patched_dir):
    """
    Copy a Hugging Face LoRA checkpoint locally and remove
    adapter config keys unsupported by the installed PEFT version.
    """

    source_dir = Path(source_dir)
    patched_dir = Path(patched_dir)

    if patched_dir.exists():
        shutil.rmtree(patched_dir)

    shutil.copytree(source_dir, patched_dir)

    config_path = patched_dir / "adapter_config.json"

    with open(config_path, "r", encoding="utf-8") as file:
        config = json.load(file)

    allowed_keys = set(
        inspect.signature(LoraConfig.__init__).parameters
    )
    allowed_keys.discard("self")

    patched_config = {
        key: value
        for key, value in config.items()
        if key in allowed_keys
    }

    for key in [
        "auto_mapping",
        "base_model_name_or_path",
        "peft_type",
        "revision",
        "task_type",
    ]:
        if key in config:
            patched_config[key] = config[key]

    removed_keys = sorted(
        set(config) - set(patched_config)
    )

    with open(config_path, "w", encoding="utf-8") as file:
        json.dump(patched_config, file, indent=2)

    if removed_keys:
        print("Removed unsupported adapter config keys:")
        for key in removed_keys:
            print(f"- {key}")

    return patched_dir


def main():
    base_dir = Path(__file__).resolve().parent
    metadata_root = (
        base_dir.parent /
        "secure-assist" /
        "enriched"
    )
    checkpoint_path = (
        base_dir /
        "checkpoints" /
        EXPERIMENT_NAME
    )
    checkpoint_path.mkdir(
        parents=True,
        exist_ok=True,
    )

    print("\n===== HF LATEST TEST =====")
    print(f"checkpoint: {HF_CHECKPOINT}")

    model = SecureCodingModel()
    evaluator = Evaluator()

    _, _, test_data = model.load_dataset(
        metadata_root
    )

    local_checkpoint = snapshot_download(
        repo_id=HF_CHECKPOINT,
        repo_type="model",
    )

    print(f"local checkpoint: {local_checkpoint}")

    patched_checkpoint = patch_adapter_config(
        source_dir=local_checkpoint,
        patched_dir=checkpoint_path / "patched_hf_checkpoint",
    )

    model.load_checkpoint(
        patched_checkpoint
    )

    test_results = model.test(
        test_data,
        evaluator,
    )

    with open(checkpoint_path / "test_results.json", "w") as file:
        json.dump(test_results, file, indent=4)

    with open(checkpoint_path / "training_config.json", "w") as file:
        json.dump(model.training_config, file, indent=4)

    print(f"\nTest results saved to: {checkpoint_path}")


if __name__ == "__main__":
    main()
