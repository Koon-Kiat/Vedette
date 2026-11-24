"""Small statistics helpers for the evaluation report."""

import math

#: Two-sided 95% normal quantile.
Z95 = 1.959963984540054


def wilson(successes: int, trials: int, z: float = Z95) -> tuple[float, float] | None:
    """The Wilson score interval for a proportion; ``None`` without trials.

    Unlike the plain normal interval it stays inside 0 to 1 and gives a useful
    upper bound when nothing succeeded (about 3.7 / n at 95%).
    """
    if trials <= 0:
        return None
    if not 0 <= successes <= trials:
        raise ValueError("successes must be between 0 and trials")
    p = successes / trials
    z2 = z * z
    centre = (p + z2 / (2 * trials)) / (1 + z2 / trials)
    margin = z * math.sqrt(p * (1 - p) / trials + z2 / (4 * trials * trials)) / (1 + z2 / trials)
    return max(0.0, centre - margin), min(1.0, centre + margin)
