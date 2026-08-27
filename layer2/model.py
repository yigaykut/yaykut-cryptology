"""Distinguisher models.

They are deliberately small. The goal is not to find the best model but to
measure WHETHER A SIGNAL EXISTS. If a small model catches the signal, the
signal is strong; if it does not, trying a larger one is worthwhile.

The approach from Gohr's 2019 CRYPTO work, scaled down: a network working on
raw bits with no feature extraction beforehand.
"""

from __future__ import annotations

import torch
import torch.nn as nn


class LengthModel(nn.Module):
    """Experiment 1, predicting the formula from length alone.

    Input: the 16 bit binary representation of the length.
    Output: a probability distribution over the corpus formulas.
    """

    def __init__(self, class_count: int, input_bits: int = 16, hidden: int = 256):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_bits, hidden), nn.ReLU(),
            nn.Linear(hidden, hidden), nn.ReLU(),
            nn.Linear(hidden, class_count),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class ContentModel(nn.Module):
    """Experiment 2, real or random from the raw bits.

    A convolution layer looks for local patterns in the bit sequence, followed
    by a fully connected classifier. The kernel is 8 bits wide with stride 8
    so it can catch structure at a byte boundary.
    """

    def __init__(self, input_bits: int, channels: int = 32, hidden: int = 128):
        super().__init__()
        self.conv = nn.Sequential(
            nn.Conv1d(1, channels, kernel_size=8, stride=8), nn.ReLU(),
            nn.Conv1d(channels, channels, kernel_size=3, padding=1), nn.ReLU(),
            nn.AdaptiveAvgPool1d(16),
        )
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(channels * 16, hidden), nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden, 2),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.classifier(self.conv(x.unsqueeze(1)))


def parameter_count(model: nn.Module) -> int:
    return sum(p.numel() for p in model.parameters() if p.requires_grad)
