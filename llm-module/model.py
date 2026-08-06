from pathlib import Path
from collections import defaultdict
from utils import (
    metric_dict,
    precision_recall,
    print_group_stats,
    print_pr_stats,
    pr_dict,
    update_per_cwe_pr_counts,
    update_pr_counts,
)

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
        #
        # max_new_tokens caps the reply. A file with many findings needs one
        # JSON object per finding, each carrying an origin and a replacement,
        # so 768 runs out at roughly eight findings and the reply is cut
        # mid-structure. Raising the cap costs nothing on short replies —
        # generation still stops at the end-of-sequence token.
        self.generation_config = {
            "do_sample": False,
            "max_new_tokens": 2048,
        }

        # Longest prompt the model is given at inference, in tokens.
        #
        # Deliberately separate from training_config["max_length"]: that value
        # is the sequence length used for fine-tuning, and reusing it here
        # silently truncated any file longer than about 250 lines of Java, so
        # findings past the cut could not be seen. Qwen2.5-Coder supports a
        # 32k context natively, well beyond this.
        self.inference_max_input = 8192

        # Experiment configuration (tunable between runs).
        self.training_config = {
            "model_name": "Qwen/Qwen2.5-Coder-7B-Instruct",
            "prompt_version": "v3",
            "max_length": 2048,
            "epochs": 3,
            "learning_rate": 1e-4,
            "lora_rank": 8,
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
    
        print(f"Loading checkpoint from {checkpoint_dir}")
    
        self.tokenizer = AutoTokenizer.from_pretrained(
            checkpoint_dir,
            trust_remote_code=True,
        )
    
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = (
                self.tokenizer.eos_token
            )
    
        self.tokenizer.padding_side = "left"
        self.tokenizer.truncation_side = "left"
    
        # Recreate quantized base model.
        base_model = (
            AutoModelForCausalLM
            .from_pretrained(
                self.training_config["model_name"],
                device_map="auto",
                trust_remote_code=True,
                quantization_config=
                    self.quantization_config,
            )
        )
    
        self.model = (
            PeftModel.from_pretrained(
                base_model,
                checkpoint_dir,
            )
        )

        # Keep generation deterministic, but make sure checkpoint
        # inference does not stop immediately on missing token IDs.
        self.generation_config["pad_token_id"] = (
            self.tokenizer.pad_token_id
        )
        self.generation_config["eos_token_id"] = (
            self.tokenizer.eos_token_id
        )
        self.generation_config.setdefault(
            "min_new_tokens",
            5,
        )
    
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


    def build_input(self, code, static_findings):
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
            .replace(
                "{static_findings}",
                json.dumps(static_findings, indent=2)
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
            max_length=self.inference_max_input,
        )

        # Truncation here means the tail of the file was never analysed, which
        # is invisible in the reply. Say so rather than silently under-report.
        if inputs["input_ids"].shape[1] >= self.inference_max_input:
            print(
                "[warn] prompt hit the "
                f"{self.inference_max_input}-token limit; "
                "the end of this file was not analysed"
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

        if not generation_config.get("do_sample", False):
            generation_config.pop("temperature", None)
            generation_config.pop("top_p", None)
            generation_config.pop("top_k", None)

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

        try:
            return self.extract_json(text)
        except ValueError as error:
            retry_config = generation_config.copy()
            retry_config.update(
                {
                    "do_sample": True,
                    "temperature": 0.2,
                    "top_p": 0.9,
                    "min_new_tokens": 20,
                }
            )

            outputs = self.model.generate(
                **inputs,
                **retry_config,
            )

            generated = outputs[0][prompt_len:]

            text = self.tokenizer.decode(
                generated,
                skip_special_tokens=True,
            )

            print("\n===== MODEL OUTPUT RETRY =====")
            print(text)
            print("==============================\n")

            try:
                return self.extract_json(text)
            except ValueError:
                raise error


    def predict(self, code, static_findings):
        """
        Generate structured vulnerability prediction.
        """

        if self.model is None:
            raise RuntimeError("Model must be loaded.")

        input_text = self.build_input(
            code,
            static_findings,
        )

        return self._generate_json(input_text)


    def _extract_predicted_cwes(self, prediction):
        """
        Extract predicted CWE IDs
        from a model response.
        """

        if not isinstance(prediction, dict):
            return set()

        vulnerabilities = prediction.get(
            "vulnerabilities",
            [],
        )

        if not isinstance(vulnerabilities, list):
            return set()

        return {
            vulnerability.get("cwe")
            for vulnerability in vulnerabilities
            if isinstance(vulnerability, dict)
            and isinstance(vulnerability.get("cwe"), str)
        }


    def load_dataset(self, metadata_root):
        """
        Load metadata files, resolve source code,
        and split samples into train/val/test.
        """
        
        repo_root = Path(__file__).resolve().parent.parent
        
        train_data, val_data, test_data = [], [], []
        metadata_root = Path(metadata_root)

        for json_file in metadata_root.rglob("*.json"):
            with open(json_file, "r", encoding="utf-8-sig") as f:
                metadata = json.load(f)

            # Source code path is stored inside metadata.
            code_path = repo_root / metadata["path"].lstrip("/")

            with open(code_path, "r", encoding="utf-8") as f:
                code = f.read()

            sample = {
                "code": code,
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
            overall_pr = pr_dict()
            per_cwe_pr = defaultdict(pr_dict)
            per_language_pr = defaultdict(pr_dict)

            with torch.no_grad():
                for sample in val_data:

                    try:
                        pred = self.predict(
                            sample["code"],
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
                    gt_cwes = set(sample["cwes"])
                    pred_cwes = self._extract_predicted_cwes(pred)

                    update_pr_counts(
                        overall_pr,
                        gt_cwes,
                        pred_cwes,
                    )

                    update_per_cwe_pr_counts(
                        per_cwe_pr,
                        gt_cwes,
                        pred_cwes,
                    )

                    update_pr_counts(
                        per_language_pr[sample["language"]],
                        gt_cwes,
                        pred_cwes,
                    )

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

            val_precision, val_recall = precision_recall(overall_pr)

            print(
                f"Validation precision/recall | "
                f"Precision: {val_precision:.4f} | "
                f"Recall: {val_recall:.4f} | "
                f"TP: {overall_pr['tp']} | "
                f"FP: {overall_pr['fp']} | "
                f"FN: {overall_pr['fn']}"
            )

            print_group_stats("Per-CWE validation:", per_cwe)
            print_group_stats("Per-language validation:", per_language)
            print_pr_stats("Per-CWE validation precision/recall:", per_cwe_pr)
            print_pr_stats(
                "Per-language validation precision/recall:",
                per_language_pr,
            )


            # Save best checkpoint based on final score
            if val_final_score > best_score:
                best_score = val_final_score
                self.save_checkpoint(checkpoint_path / "best")
                print("\nNew best checkpoint.")

        print("\nTraining completed.")


    def _repair_invalid_json_escapes(self, text):
        """
        Remove invalid backslash escapes
        from model-generated JSON text.
        """

        valid_escapes = {
            '"',
            "\\",
            "/",
            "b",
            "f",
            "n",
            "r",
            "t",
            "u",
        }

        repaired = []
        index = 0

        while index < len(text):
            char = text[index]

            if (
                char == "\\"
                and index + 1 < len(text)
            ):
                next_char = text[index + 1]

                if next_char in valid_escapes:
                    repaired.append(char)
                    repaired.append(next_char)
                else:
                    repaired.append(next_char)

                index += 2
                continue

            repaired.append(char)
            index += 1

        return "".join(repaired)


    def _escape_stray_quotes(self, text):
        """
        Escape quotes the model left unescaped inside a string.

        Java and C code is full of string literals, and the model sometimes
        writes one into a JSON value without escaping it — an empty string
        emitted as "" rather than \\"\\". Everything after that point is
        misread, so a single missing backslash can cost every finding in the
        reply.

        A closing quote is only genuine where the grammar allows one: a key
        ends before a colon, a value ends before a comma or a closing brace
        or bracket. A quote anywhere else inside a string is content, and is
        escaped here. Key and value positions are tracked separately because
        the two have different terminators.
        """

        out = []
        index = 0
        length = len(text)

        in_string = False
        is_key = False
        expecting_value = False

        while index < length:
            char = text[index]

            if not in_string:
                if char == '"':
                    in_string = True
                    is_key = not expecting_value
                elif char == ":":
                    expecting_value = True
                elif char in ",{[":
                    expecting_value = False

                out.append(char)
                index += 1
                continue

            # Inside a string.
            if char == "\\" and index + 1 < length:
                out.append(char)
                out.append(text[index + 1])
                index += 2
                continue

            if char == '"':
                lookahead = index + 1
                while lookahead < length and text[lookahead] in " \t\r\n":
                    lookahead += 1

                following = text[lookahead] if lookahead < length else ""
                terminator = ":" if is_key else ",}]"

                if following in terminator and following != "":
                    in_string = False
                    out.append(char)
                else:
                    # Content, not a terminator: the model forgot the escape.
                    out.append('\\"')

                index += 1
                continue

            out.append(char)
            index += 1

        return "".join(out)


    def _salvage_truncated_json(self, text):
        """
        Recover the longest prefix of a malformed reply that still parses.

        Two things go wrong with generated JSON. A long reply is cut at
        max_new_tokens, mid-object. And the model sometimes writes a quote
        inside a string without escaping it — a Java empty-string literal
        emitted as "" rather than \\"\\" — which corrupts the reply from that
        point on. Either way the entries before the damage are valid, and
        discarding them loses real detections.

        Structural balance alone is not enough to find the cut: an unescaped
        quote flips the in-string state, so brace counting drifts and happily
        "balances" past the corruption. Each candidate cut is therefore
        actually parsed, and the longest one that decodes wins.

        Returns None when no prefix parses.
        """

        decoder = json.JSONDecoder()

        depth = 0
        in_string = False
        escaped = False
        candidates = []

        for index, char in enumerate(text):
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue

            if char == '"':
                in_string = True
            elif char in "{[":
                depth += 1
            elif char in "}]":
                depth -= 1
                if depth < 0:
                    break
                # A closed object sitting directly inside the outer
                # object's array is a complete entry we could keep.
                if depth == 2:
                    candidates.append(index)

        # Longest first: prefer keeping as many entries as possible.
        for cut in reversed(candidates):
            candidate_text = text[: cut + 1] + "]}"

            try:
                decoder.raw_decode(candidate_text)
                return candidate_text
            except json.JSONDecodeError:
                continue

        return None


    def extract_json(self, text):
        start = text.find("{")

        if start == -1:
            raise ValueError("No JSON found.")

        decoder = json.JSONDecoder()
        json_text = text[start:]

        try:
            obj, _ = decoder.raw_decode(json_text)
            return obj
        except json.JSONDecodeError as error:
            repaired_text = self._repair_invalid_json_escapes(
                json_text
            )

            try:
                obj, _ = decoder.raw_decode(repaired_text)
                return obj
            except json.JSONDecodeError as repaired_error:
                # A stray unescaped quote corrupts everything after it, so
                # try repairing those before falling back to discarding the
                # damaged tail.
                escaped_text = self._escape_stray_quotes(
                    repaired_text
                )

                try:
                    obj, _ = decoder.raw_decode(escaped_text)

                    print(
                        "[warn] reply contained unescaped quotes; "
                        "repaired them"
                    )

                    return obj
                except json.JSONDecodeError:
                    pass

                salvaged_text = self._salvage_truncated_json(
                    escaped_text
                )

                if salvaged_text is not None:
                    try:
                        obj, _ = decoder.raw_decode(salvaged_text)

                        print(
                            "[warn] reply was truncated; "
                            "recovered the complete prefix"
                        )

                        return obj
                    except json.JSONDecodeError:
                        pass

                raise ValueError(
                    f"Invalid JSON: {repaired_error}"
                ) from error
    

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

        overall_pr = pr_dict()
        per_cwe_pr = defaultdict(pr_dict)
        per_language_pr = defaultdict(pr_dict)

        with torch.no_grad():
            for sample in test_data:

                try:
                    pred = self.predict(
                        sample["code"],
                        sample["static_findings"],
                    )
                except Exception as e:
                    print(f"Test failure: {e}")
                    pred = {"vulnerabilities": []}

                scores = evaluator.evaluate(sample, pred)
                gt_cwes = set(sample["cwes"])
                pred_cwes = self._extract_predicted_cwes(pred)

                update_pr_counts(
                    overall_pr,
                    gt_cwes,
                    pred_cwes,
                )

                update_per_cwe_pr_counts(
                    per_cwe_pr,
                    gt_cwes,
                    pred_cwes,
                )

                update_pr_counts(
                    per_language_pr[sample["language"]],
                    gt_cwes,
                    pred_cwes,
                )

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

        test_precision, test_recall = precision_recall(overall_pr)

        print(
            f"Test precision/recall | "
            f"Precision: {test_precision:.4f} | "
            f"Recall: {test_recall:.4f} | "
            f"TP: {overall_pr['tp']} | "
            f"FP: {overall_pr['fp']} | "
            f"FN: {overall_pr['fn']}"
        )

        print_group_stats("Per-CWE test:", per_cwe)
        print_group_stats("Per-language test:", per_language)
        print_pr_stats("Per-CWE test precision/recall:", per_cwe_pr)
        print_pr_stats(
            "Per-language test precision/recall:",
            per_language_pr,
        )

        return {
            "final_score": test_final_score,
            "cwe_score": test_cwe_score,
            "fix_score": test_fix_score,
            "precision": test_precision,
            "recall": test_recall,
        }
