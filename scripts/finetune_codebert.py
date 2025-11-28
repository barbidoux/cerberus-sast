#!/usr/bin/env python3
"""
Fine-tune CodeBERT for Vulnerability Classification using LoRA.

This script fine-tunes microsoft/codebert-base for binary classification
(vulnerable vs safe) using Parameter-Efficient Fine-Tuning (PEFT) with LoRA.

Requirements:
    pip install torch transformers peft datasets accelerate

Usage:
    python scripts/finetune_codebert.py --data data/training_data.jsonl --output models/codebert-vuln

Hardware requirements:
    - Minimum: 8GB VRAM (with gradient checkpointing)
    - Recommended: 16GB VRAM (RTX 4090 Laptop)
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def check_dependencies() -> bool:
    """Check if required dependencies are available."""
    try:
        import torch
        import transformers
        import peft
        import datasets
        logger.info(f"PyTorch version: {torch.__version__}")
        logger.info(f"Transformers version: {transformers.__version__}")
        logger.info(f"PEFT version: {peft.__version__}")
        logger.info(f"CUDA available: {torch.cuda.is_available()}")
        if torch.cuda.is_available():
            logger.info(f"CUDA device: {torch.cuda.get_device_name(0)}")
            logger.info(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")
        return True
    except ImportError as e:
        logger.error(f"Missing dependency: {e}")
        logger.error("Install with: pip install torch transformers peft datasets accelerate")
        return False


def load_dataset(data_path: Path, val_split: float = 0.1):
    """Load and prepare the dataset."""
    from datasets import Dataset, DatasetDict

    # Load JSONL
    examples = []
    with open(data_path) as f:
        for line in f:
            examples.append(json.loads(line))

    logger.info(f"Loaded {len(examples)} examples from {data_path}")

    # Create dataset
    dataset = Dataset.from_list(examples)

    # Split into train/val
    split = dataset.train_test_split(test_size=val_split, seed=42)

    return DatasetDict({
        "train": split["train"],
        "validation": split["test"],
    })


def create_model_and_tokenizer(
    model_name: str = "microsoft/codebert-base",
    lora_r: int = 8,
    lora_alpha: int = 16,
    lora_dropout: float = 0.1,
):
    """Create the model with LoRA adapters."""
    from transformers import RobertaTokenizer, RobertaForSequenceClassification
    from peft import LoraConfig, get_peft_model, TaskType

    logger.info(f"Loading base model: {model_name}")

    # Load tokenizer
    tokenizer = RobertaTokenizer.from_pretrained(model_name)

    # Load model for sequence classification
    model = RobertaForSequenceClassification.from_pretrained(
        model_name,
        num_labels=2,
        problem_type="single_label_classification",
    )

    # Configure LoRA
    lora_config = LoraConfig(
        task_type=TaskType.SEQ_CLS,
        r=lora_r,
        lora_alpha=lora_alpha,
        lora_dropout=lora_dropout,
        target_modules=["query", "value"],  # Apply LoRA to attention layers
        inference_mode=False,
    )

    # Apply LoRA
    model = get_peft_model(model, lora_config)

    # Log trainable parameters
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total_params = sum(p.numel() for p in model.parameters())
    logger.info(f"Trainable parameters: {trainable_params:,} ({100 * trainable_params / total_params:.2f}%)")

    return model, tokenizer


def tokenize_function(examples, tokenizer, max_length: int = 512):
    """Tokenize examples for the model."""
    return tokenizer(
        examples["text"],
        padding="max_length",
        truncation=True,
        max_length=max_length,
    )


def compute_metrics(eval_pred):
    """Compute evaluation metrics."""
    import numpy as np
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support

    predictions, labels = eval_pred
    predictions = np.argmax(predictions, axis=1)

    accuracy = accuracy_score(labels, predictions)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average="binary"
    )

    # Calculate true positive rate (recall for vulnerable class)
    tp_rate = recall  # For binary classification, recall = TP / (TP + FN)

    # Calculate false positive rate
    tn = np.sum((predictions == 0) & (labels == 0))
    fp = np.sum((predictions == 1) & (labels == 0))
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp_rate": tp_rate,
        "fp_rate": fp_rate,
    }


def train(
    data_path: Path,
    output_dir: Path,
    model_name: str = "microsoft/codebert-base",
    epochs: int = 3,
    batch_size: int = 8,
    learning_rate: float = 2e-5,
    lora_r: int = 8,
    lora_alpha: int = 16,
    gradient_checkpointing: bool = False,
    fp16: bool = True,
):
    """Run the training loop."""
    import torch
    from transformers import Trainer, TrainingArguments

    # Load dataset
    dataset = load_dataset(data_path)

    # Create model and tokenizer
    model, tokenizer = create_model_and_tokenizer(
        model_name=model_name,
        lora_r=lora_r,
        lora_alpha=lora_alpha,
    )

    # Enable gradient checkpointing for memory efficiency
    if gradient_checkpointing:
        model.gradient_checkpointing_enable()
        logger.info("Gradient checkpointing enabled")

    # Tokenize dataset
    tokenized_dataset = dataset.map(
        lambda x: tokenize_function(x, tokenizer),
        batched=True,
        remove_columns=["text"],
    )

    # Training arguments
    training_args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        per_device_eval_batch_size=batch_size * 2,
        learning_rate=learning_rate,
        weight_decay=0.01,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        fp16=fp16 and torch.cuda.is_available(),
        logging_dir=str(output_dir / "logs"),
        logging_steps=50,
        report_to="none",  # Disable wandb/tensorboard
        seed=42,
    )

    # Create trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_dataset["train"],
        eval_dataset=tokenized_dataset["validation"],
        tokenizer=tokenizer,
        compute_metrics=compute_metrics,
    )

    # Train
    logger.info("Starting training...")
    train_result = trainer.train()

    # Save model
    logger.info(f"Saving model to {output_dir}")
    trainer.save_model()
    tokenizer.save_pretrained(output_dir)

    # Save training metrics
    metrics = train_result.metrics
    trainer.log_metrics("train", metrics)
    trainer.save_metrics("train", metrics)

    # Evaluate
    logger.info("Running final evaluation...")
    eval_metrics = trainer.evaluate()
    trainer.log_metrics("eval", eval_metrics)
    trainer.save_metrics("eval", eval_metrics)

    # Print summary
    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)
    print(f"Model saved to: {output_dir}")
    print(f"\nFinal Metrics:")
    print(f"  Accuracy:    {eval_metrics.get('eval_accuracy', 0):.4f}")
    print(f"  Precision:   {eval_metrics.get('eval_precision', 0):.4f}")
    print(f"  Recall:      {eval_metrics.get('eval_recall', 0):.4f}")
    print(f"  F1 Score:    {eval_metrics.get('eval_f1', 0):.4f}")
    print(f"  TP Rate:     {eval_metrics.get('eval_tp_rate', 0):.4f}")
    print(f"  FP Rate:     {eval_metrics.get('eval_fp_rate', 0):.4f}")
    print("=" * 60)

    return trainer, eval_metrics


def main():
    parser = argparse.ArgumentParser(
        description="Fine-tune CodeBERT for vulnerability classification"
    )
    parser.add_argument(
        "--data",
        type=Path,
        default=Path("data/training_data.jsonl"),
        help="Path to training data JSONL",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("models/codebert-vuln"),
        help="Output directory for model",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="microsoft/codebert-base",
        help="Base model to fine-tune",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=3,
        help="Number of training epochs",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=8,
        help="Batch size (reduce if OOM)",
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=2e-5,
        help="Learning rate",
    )
    parser.add_argument(
        "--lora-r",
        type=int,
        default=8,
        help="LoRA rank (lower = fewer params)",
    )
    parser.add_argument(
        "--lora-alpha",
        type=int,
        default=16,
        help="LoRA alpha scaling",
    )
    parser.add_argument(
        "--gradient-checkpointing",
        action="store_true",
        help="Enable gradient checkpointing (saves VRAM)",
    )
    parser.add_argument(
        "--no-fp16",
        action="store_true",
        help="Disable FP16 training",
    )

    args = parser.parse_args()

    # Check dependencies
    if not check_dependencies():
        return 1

    # Check data file
    if not args.data.exists():
        logger.error(f"Data file not found: {args.data}")
        logger.info("Generate training data first:")
        logger.info("  python -m cerberus.ml.training_data --output data/training_data.jsonl")
        return 1

    # Create output directory
    args.output.mkdir(parents=True, exist_ok=True)

    # Run training
    train(
        data_path=args.data,
        output_dir=args.output,
        model_name=args.model,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        lora_r=args.lora_r,
        lora_alpha=args.lora_alpha,
        gradient_checkpointing=args.gradient_checkpointing,
        fp16=not args.no_fp16,
    )

    return 0


if __name__ == "__main__":
    exit(main())
