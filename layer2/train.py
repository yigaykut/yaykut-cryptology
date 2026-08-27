"""Training loop.

Reproducibility is essential: when an experiment says "the model could not
tell them apart", that claim has to be testable again under the same seed.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


@dataclass
class TrainingResult:
    model: nn.Module
    y_true: np.ndarray
    y_pred: np.ndarray
    score: np.ndarray         # probability of class 1, for binary experiments
    final_loss: float
    epochs: int


def set_seed(seed: int = 0) -> None:
    torch.manual_seed(seed)
    np.random.seed(seed)


def train_model(
    model: nn.Module,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    *,
    epochs: int = 20,
    batch: int = 256,
    lr: float = 1e-3,
    seed: int = 0,
    quiet: bool = True,
) -> TrainingResult:
    """Trains the model and returns its predictions on the TEST set.

    The test set is never seen during training. Accuracy is always reported
    on it, because training accuracy measures memorisation, not leakage.
    """
    set_seed(seed)
    model = model.to(DEVICE)

    loader = DataLoader(
        TensorDataset(torch.from_numpy(X_train), torch.from_numpy(y_train)),
        batch_size=batch,
        shuffle=True,
    )
    optim = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.CrossEntropyLoss()

    final_loss = float("nan")
    for e in range(epochs):
        model.train()
        total, count = 0.0, 0
        for xb, yb in loader:
            xb, yb = xb.to(DEVICE), yb.to(DEVICE)
            optim.zero_grad()
            loss = loss_fn(model(xb), yb)
            loss.backward()
            optim.step()
            total += loss.item() * len(yb)
            count += len(yb)
        final_loss = total / count
        if not quiet:
            print(f"    epoch {e + 1:>3}/{epochs}  loss={final_loss:.4f}")

    model.eval()
    predictions, scores = [], []
    with torch.no_grad():
        for i in range(0, len(X_test), 1024):
            xb = torch.from_numpy(X_test[i:i + 1024]).to(DEVICE)
            out = model(xb)
            probability = torch.softmax(out, dim=1)
            predictions.append(out.argmax(dim=1).cpu().numpy())
            scores.append(probability[:, 1].cpu().numpy() if probability.shape[1] == 2
                          else probability.max(dim=1).values.cpu().numpy())

    return TrainingResult(
        model=model,
        y_true=y_test,
        y_pred=np.concatenate(predictions),
        score=np.concatenate(scores),
        final_loss=final_loss,
        epochs=epochs,
    )
