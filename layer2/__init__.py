"""layer2: the AI attacker layer.

The neural network does NOT decrypt here. It AUDITS the cipher, trying to
tell the ciphertexts we produce apart from random noise.

  Cannot tell them apart -> empirical evidence for the design
  Can tell them apart    -> a weakness was found, fix it and try again

Both outcomes are valuable (ADR-001).
"""

from .train import DEVICE, TrainingResult, set_seed, train_model
from .model import ContentModel, LengthModel, parameter_count
from .metrics import (
    accuracy,
    auc,
    beats_chance,
    collapsed,
    confusion,
    per_class_accuracy,
    report_binary,
    wilson_interval,
)
from .data import (
    ciphertext,
    content_data,
    frame_data,
    length_ceiling,
    length_data,
    sabotaged_ciphertext,
    split_data,
)

__all__ = [
    "train_model", "TrainingResult", "set_seed", "DEVICE",
    "LengthModel", "ContentModel", "parameter_count",
    "accuracy", "auc", "wilson_interval", "beats_chance",
    "confusion", "per_class_accuracy", "report_binary", "collapsed",
    "length_data", "length_ceiling", "content_data", "frame_data", "split_data",
    "ciphertext", "sabotaged_ciphertext",
]
