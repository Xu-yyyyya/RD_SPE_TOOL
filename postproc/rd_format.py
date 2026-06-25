#!/usr/bin/env python3
"""Shared presentation helpers for RD post-processing reports."""

from __future__ import annotations

import math
from typing import Tuple


Bucket = Tuple[int, int]


def format_rd_value(value: int) -> str:
    """Format large reuse-distance values in compact scientific notation."""
    value = int(value)
    if abs(value) < 10000:
        return str(value)
    exponent = int(math.floor(math.log10(abs(value))))
    mantissa = value / (10 ** exponent)
    return f"{mantissa:.1f}E{exponent}"


def format_rd_bucket(bucket: Bucket) -> str:
    """Return a compact label for a log2 reuse-distance bucket."""
    lo, hi = bucket
    if lo == hi:
        return format_rd_value(lo)
    return f"{format_rd_value(lo)}-{format_rd_value(hi)}"
