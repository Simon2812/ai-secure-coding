from pathlib import Path
from collections import defaultdict
from utils import metric_dict, print_group_stats

import json
import random
import torch

from torch.optim import AdamW
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig,
)
from peft import LoraConfig, get_peft_model, PeftModel


class SecureCodingModel:
    """
    Secure coding LLM module.

    Responsibilities:
    - load quantized base model
    - attach LoRA adapters
    - load analyzer-enriched dataset
    - perform inference
    - fine-tune using supervised learning
    - validate through external evaluator
    - save and restore checkpoints
    """

    def __init__(self):
        """
        Initialize model identifiers,
        generation settings and training settings.
        """
        self.model = None
        self.tokenizer = None

        # Deterministic JSON generation.
        self.generation_config = {
            "do_sample": False,
            "max_new_tokens": 256,
        }

        # Experiment configuration (tunable between runs).
        self.training_config = {
            "model_name": "Qwen/Qwen2.5-Coder-7B-Instruct",
            "prompt_version": "v2",
            "max_length": 2048,
            "epochs": 3,
            "learning_rate": 2e-4,
            "lora_rank": 16,
        }

        # Shared QLoRA quantization config.
        self.quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4",
        )


    def load_model(self):
        """
        Load quantized base model
        and attach trainable LoRA adapters.
        """

        print(f"Loading model: {self.training_config['model_name']}")

        self.tokenizer = AutoTokenizer.from_pretrained(
            self.training_config["model_name"],
            trust_remote_code=True,
        )

        # Some models do not define pad token.
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        # Qwen usually behaves better with left padding.
        self.tokenizer.padding_side = "left"
        self.tokenizer.truncation_side = "left"

        # Explicit generation tokens for stable decoding.
        self.generation_config["pad_token_id"] = self.tokenizer.eos_token_id
        self.generation_config["eos_token_id"] = self.tokenizer.eos_token_id

        self.model = AutoModelForCausalLM.from_pretrained(
            self.training_config["model_name"],
            device_map="auto",
            trust_remote_code=True,
            quantization_config=self.quantization_config,
        )

        # LoRA enables lightweight fine-tuning.
        # Explicit Qwen attention modules.
        lora_config = LoraConfig(
            r=self.training_config["lora_rank"],
            lora_alpha=32,
            lora_dropout=0.05,
            bias="none",
            task_type="CAUSAL_LM",
            target_modules=[
                "q_proj",
                "k_proj",
                "v_proj",
                "o_proj",
            ],
        )

        self.model = get_peft_model(self.model, lora_config)

        self.model.print_trainable_parameters()
        print("Model loaded successfully.")


    def load_checkpoint(self, checkpoint_dir):
        """
        Restore trained LoRA adapters
        from an existing checkpoint.
        """

        checkpoint_path = Path(checkpoint_dir)

        if not checkpoint_path.exists():
            raise FileNotFoundError(
                f"Checkpoint not found: {checkpoint_path}"
            )

        print(f"Loading checkpoint from {checkpoint_path}")

        self.tokenizer = AutoTokenizer.from_pretrained(
            checkpoint_path,
            trust_remote_code=True,
        )

        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        self.tokenizer.padding_side = "left"
        self.tokenizer.truncation_side = "left"

        # Recreate quantized base model.
        base_model = AutoModelForCausalLM.from_pretrained(
            self.training_config["model_name"],
            device_map="auto",
            trust_remote_code=True,
            quantization_config=self.quantization_config,
        )

        self.model = PeftModel.from_pretrained(
            base_model,
            checkpoint_path,
        )

        # Restore generation settings.
        gen_path = checkpoint_path / "generation_config.json"
        if gen_path.exists():
            with open(gen_path, "r") as f:
                self.generation_config = json.load(f)

        self.model.print_trainable_parameters()
        print("Checkpoint loaded.")


    def save_checkpoint(self, checkpoint_dir):
        """
        Save current LoRA weights,
        tokenizer and training config.
        """

        checkpoint_path = Path(checkpoint_dir)
        checkpoint_path.mkdir(parents=True, exist_ok=True)

        print(f"Saving checkpoint to {checkpoint_path}")

        if self.model is None:
            raise RuntimeError(
                "Cannot save checkpoint before model is loaded."
            )

        self.model.save_pretrained(checkpoint_path)
        self.tokenizer.save_pretrained(checkpoint_path)

        # Save training config.
        with open(checkpoint_path / "training_config.json", "w") as f:
            json.dump(self.training_config, f, indent=4)

        # Save generation settings for reproducible inference.
        with open(checkpoint_path / "generation_config.json", "w") as f:
            json.dump(self.generation_config, f, indent=4)

        print("Checkpoint saved.")


    def build_input(self, code, line_offset, static_findings):
        """
        Build unified prompt used for:
        - training
        - validation
        - inference
        """ 

        prompt_version = self.training_config["prompt_version"]

        prompt_path = Path(__file__).parent / "prompts" / f"{prompt_version}.txt"

        if not prompt_path.exists():
            raise FileNotFoundError(
                f"Prompt not found: {prompt_path}"
            )

        with open(prompt_path, "r", encoding="utf-8") as file:
            template = file.read()

        # Inject dynamic content.
        prompt = template \
            .replace("{code}", code) \
            .replace("{line_offset}", str(line_offset)) \
            .replace(
                "{static_findings}",
                json.dumps(static_findings, indent=2)
            )

        return prompt.strip()


    def build_regeneration_input(
        self,
        code,
        line_offset,
        static_findings,
        cwe,
        rejected_fixes,
    ):
        """
        Build prompt for
        fix regeneration.
        """

        prompt_path = (
            Path(__file__).parent
            / "prompts"
            / "regenerate_fix.txt"
        )

        if not prompt_path.exists():
            raise FileNotFoundError(
                f"Prompt not found: {prompt_path}"
            )

        with open(prompt_path, "r", encoding="utf-8") as file:
            template = file.read()

        prompt = (
            template
            .replace("{code}", code)
            .replace("{line_offset}", str(line_offset))
            .replace(
                "{static_findings}",
                json.dumps(static_findings, indent=2),
            )
            .replace("{cwe}", cwe)
            .replace(
                "{rejected_fixes}",
                json.dumps(rejected_fixes, indent=2),
            )
        )

        return prompt.strip()


    def _generate_json(
        self,
        input_text,
        generation_overrides=None,
    ):
        """
        Run model inference
        on prepared prompt.
        """

        if self.model is None:
            raise RuntimeError("Model must be loaded.")

        self.model.eval()

        inputs = self.tokenizer(
            input_text,
            return_tensors="pt",
            truncation=True,
            max_length=self.training_config["max_length"],
        )

        # Align tensors with model device.
        device = next(self.model.parameters()).device

        inputs = {
            key: value.to(device)
            for key, value in inputs.items()
        }

        generation_config = self.generation_config.copy()

        if generation_overrides:
            generation_config.update(generation_overrides)

        outputs = self.model.generate(
            **inputs,
            **generation_config,
        )

        # Decode only generated tokens.
        prompt_len = inputs["input_ids"].shape[1]
        generated = outputs[0][prompt_len:]

        text = self.tokenizer.decode(
            generated,
            skip_special_tokens=True,
        )

        print("\n===== MODEL OUTPUT =====")
        print(text)
        print("========================\n")

        return self.extract_json(text)


    def predict(self, code, line_offset, static_findings):
        """
        Generate structured vulnerability prediction.
        """

        if self.model is None:
            raise RuntimeError("Model must be loaded.")

        input_text = self.build_input(
            code,
            line_offset,
            static_findings,
        )

        return self._generate_json(input_text)


    def regenerate_fix(
        self,
        code,
        line_offset,
        static_findings,
        cwe,
        rejected_fixes,
    ):
        """
        Generate alternative fixes
        for one vulnerability.
        """

        if self.model is None:
            raise RuntimeError("Model must be loaded.")

        input_text = self.build_regeneration_input(
            code,
            line_offset,
            static_findings,
            cwe,
            rejected_fixes,
        )

        return self._generate_json(
            input_text,
            generation_overrides={
                "temperature": 0.2,
                "do_sample": True,
            },
        )


    def load_dataset(self, metadata_root):
        """
        Load metadata files, resolve source code,
        and split samples into train/val/test.
        """
        
        repo_root = Path(__file__).resolve().parent.parent
        
        train_data, val_data, test_data = [], [], []
        metadata_root = Path(metadata_root)

        for json_file in metadata_root.rglob("*.json"):
            with open(json_file, "r", encoding="utf-8") as f:
                metadata = json.load(f)

            # Source code path is stored inside metadata.
            code_path = repo_root / metadata["path"].lstrip("/")

            with open(code_path, "r", encoding="utf-8") as f:
                code = f.read()

            sample = {
                "code": code,
                "line_offset": 0,  # Can be used for line number adjustments if needed.
                "target": metadata["vulnerabilities"],
                "split": metadata["split"],
                "language": metadata["language"],
                "static_findings": metadata["static_findings"],
                "cwes": [
                            vuln["cwe"]
                            for vuln in metadata[
                                "vulnerabilities"
                            ]
                ],
            }

            split = sample["split"]

            if split == "train":
                train_data.append(sample)
            elif split == "val":
                val_data.append(sample)
            elif split == "test":
                test_data.append(sample)
            else:
                raise ValueError(f"Unknown split: {split}")

        print(
            f"Loaded {len(train_data)} train, "
            f"{len(val_data)} val, {len(test_data)} test samples."
        )

        return train_data, val_data, test_data
    

    def train(self, train_data, val_data, evaluator, checkpoint_path):
        """
        Fine-tune LoRA adapters on train split.
        Validation runs after each epoch.
        """

        if self.model is None:
            raise RuntimeError("Model must be loaded.")

        optimizer = AdamW(
            filter(lambda p: p.requires_grad, self.model.parameters()),
            lr=self.training_config["learning_rate"],
        )

        best_score = -1

        for epoch in range(self.training_config["epochs"]):
            print(
                f"\nEpoch {epoch + 1}/"
                f"{self.training_config['epochs']}"
            )

            self.model.train()
            random.shuffle(train_data)

            total_loss = 0

            for sample in train_data:
                prompt = self.build_input(
                    sample["code"],
                    sample["line_offset"],
                    sample["static_findings"],
                )

                # Ground truth aligned with expected JSON format.
                target = {
                    "vulnerabilities": sample["target"]
                }
                
                target_text = "\n" + json.dumps(target, indent=2) + self.tokenizer.eos_token
                
                target_tokens = self.tokenizer(
                    target_text,
                    return_tensors="pt",
                    add_special_tokens=False,
                )
                
                max_length = self.training_config[
                    "max_length"
                ]
                
                target_len = target_tokens[
                    "input_ids"
                ].shape[1]
                
                prompt_max_length = (
                    max_length - target_len
                )
                
                if prompt_max_length <= 0:
                    continue
                
                prompt_tokens = self.tokenizer(
                    prompt,
                    return_tensors="pt",
                    truncation=True,
                    truncation_side="left",
                    max_length=prompt_max_length,
                    add_special_tokens=True,
                )
                
                input_ids = torch.cat(
                    [
                        prompt_tokens["input_ids"],
                        target_tokens["input_ids"],
                    ],
                    dim=1,
                )
                
                attention_mask = torch.ones_like(
                    input_ids
                )
                
                labels = input_ids.clone()
                
                prompt_len = prompt_tokens[
                    "input_ids"
                ].shape[1]
                
                labels[:, :prompt_len] = -100
                
                device = next(
                    self.model.parameters()
                ).device
                
                inputs = {
                    "input_ids": input_ids.to(device),
                    "attention_mask": attention_mask.to(device),
                }
                
                labels = labels.to(device)
                
                optimizer.zero_grad()
                
                loss = self.model(
                    **inputs,
                    labels=labels,
                ).loss
                
                if torch.isnan(loss):
                    print(
                        "Skipping NaN loss sample."
                    )
                    continue
                
                total_loss += loss.item()
                
                loss.backward()
                
                torch.nn.utils.clip_grad_norm_(
                    self.model.parameters(),
                    1.0,
                )
                
                optimizer.step()

            avg_loss = total_loss / len(train_data)
            print(f"Train loss: {avg_loss:.4f}")

            # ================= VALIDATION =================

            self.model.eval()

            val_final_score = 0
            val_cwe_score = 0
            val_fix_score = 0

            per_cwe = defaultdict(metric_dict)
            per_language = defaultdict(metric_dict)

            with torch.no_grad():
                for sample in val_data:

                    try:
                        pred = self.predict(
                            sample["code"],
                            sample["line_offset"],
                            sample["static_findings"],
                        )
                    except Exception as e:
                    
                        print(
                            f"Validation failure: {e}"
                        )
                    
                        pred = {
                            "vulnerabilities": []
                        }
                        
                    scores = evaluator.evaluate(sample, pred)

                    val_final_score += scores["final_score"]
                    val_cwe_score += scores["cwe_score"]
                    val_fix_score += scores["fix_score"]

                    # Per-CWE stats
                    for cwe in sample["cwes"]:
                        per_cwe[cwe]["final"].append(scores["final_score"])
                        per_cwe[cwe]["cwe"].append(scores["cwe_score"])
                        per_cwe[cwe]["fix"].append(scores["fix_score"])

                    # Per-language stats
                    lang = sample["language"]
                    per_language[lang]["final"].append(scores["final_score"])
                    per_language[lang]["cwe"].append(scores["cwe_score"])
                    per_language[lang]["fix"].append(scores["fix_score"])

            n = len(val_data)

            val_final_score /= n
            val_cwe_score /= n
            val_fix_score /= n

            print(
                f"\nValidation scores | "
                f"Final: {val_final_score:.4f} | "
                f"CWE: {val_cwe_score:.4f} | "
                f"Fix: {val_fix_score:.4f}"
            )

            print_group_stats("Per-CWE validation:", per_cwe)
            print_group_stats("Per-language validation:", per_language)

            # Save best checkpoint based on final score
            if val_final_score > best_score:
                best_score = val_final_score
                self.save_checkpoint(checkpoint_path / "best")
                print("\nNew best checkpoint.")

        print("\nTraining completed.")


    def extract_json(self, text):
        """
        Extract first complete JSON object
        from model output.
        """

        start = text.find("{")
    
        if start == -1:
            raise ValueError(
                "No JSON found."
            )
    
        depth = 0
    
        for i in range(start, len(text)):
    
            if text[i] == "{":
                depth += 1
    
            elif text[i] == "}":
                depth -= 1
    
                if depth == 0:
    
                    candidate = text[
                        start : i + 1
                    ]
    
                    return json.loads(
                        candidate
                    )
    
        raise ValueError(
            "Incomplete JSON."
        )
    

    def test(self, test_data, evaluator):
        """
        Final evaluation on unseen test split.
        """

        if self.model is None:
            raise RuntimeError("Model must be loaded.")

        self.model.eval()

        test_final_score = 0
        test_cwe_score = 0
        test_fix_score = 0

        per_cwe = defaultdict(metric_dict)
        per_language = defaultdict(metric_dict)

        with torch.no_grad():
            for sample in test_data:

                pred = self.predict(
                    sample["code"],
                    sample["line_offset"],
                    sample["static_findings"],
                )

                scores = evaluator.evaluate(sample, pred)

                test_final_score += scores["final_score"]
                test_cwe_score += scores["cwe_score"]
                test_fix_score += scores["fix_score"]

                # Per-CWE stats
                for cwe in sample["cwes"]:
                    per_cwe[cwe]["final"].append(scores["final_score"])
                    per_cwe[cwe]["cwe"].append(scores["cwe_score"])
                    per_cwe[cwe]["fix"].append(scores["fix_score"])

                # Per-language stats
                lang = sample["language"]
                per_language[lang]["final"].append(scores["final_score"])
                per_language[lang]["cwe"].append(scores["cwe_score"])
                per_language[lang]["fix"].append(scores["fix_score"])

        n = len(test_data)

        test_final_score /= n
        test_cwe_score /= n
        test_fix_score /= n

        print(
            f"\nTest scores | "
            f"Final: {test_final_score:.4f} | "
            f"CWE: {test_cwe_score:.4f} | "
            f"Fix: {test_fix_score:.4f}"
        )

        print_group_stats("Per-CWE test:", per_cwe)
        print_group_stats("Per-language test:", per_language)

        return {
            "final_score": test_final_score,
            "cwe_score": test_cwe_score,
            "fix_score": test_fix_score,
        }
