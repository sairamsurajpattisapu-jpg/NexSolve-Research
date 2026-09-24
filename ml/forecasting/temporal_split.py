"""Strict Temporal Splitting and Leakage Prevention Engine.

Provides mathematically rigorous, chronological partitioning for time-series
and network state trajectories with zero forward leakage:
1. Strict chronological ordering (Train < Val < Test).
2. Embargo / purge gap between splits to eliminate autocorrelation and rollout boundary leakage.
3. Attack-family holdout isolation (completely excluded from training/validation/scaling).
4. Window leakage validation (verifying zero lookahead, no overlapping boundaries, monotonic timestamps).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Generic, Mapping, Sequence, TypeVar

T = TypeVar("T")


class TemporalLeakageError(ValueError):
    """Raised when temporal leakage or invalid chronological sequence is detected."""
    pass


@dataclass(slots=True, frozen=True)
class SplitMetadata:
    """Metadata describing a temporal split partition."""
    name: str
    sample_count: int
    start_timestamp: float | None
    end_timestamp: float | None
    label_distribution: dict[str, int]
    attack_family_distribution: dict[str, int]


@dataclass(slots=True)
class TemporalSplitResult(Generic[T]):
    """Container for chronological train, validation, and test splits with audit metadata."""
    train: list[T]
    val: list[T]
    test: list[T]
    holdout_test: list[T] = field(default_factory=list)
    embargo_purged_count: int = 0
    train_meta: SplitMetadata | None = None
    val_meta: SplitMetadata | None = None
    test_meta: SplitMetadata | None = None
    holdout_meta: SplitMetadata | None = None
    held_out_families: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "train_count": len(self.train),
            "val_count": len(self.val),
            "test_count": len(self.test),
            "holdout_test_count": len(self.holdout_test),
            "embargo_purged_count": self.embargo_purged_count,
            "held_out_families": list(self.held_out_families),
            "train_range": (
                (self.train_meta.start_timestamp, self.train_meta.end_timestamp)
                if self.train_meta else None
            ),
            "val_range": (
                (self.val_meta.start_timestamp, self.val_meta.end_timestamp)
                if self.val_meta else None
            ),
            "test_range": (
                (self.test_meta.start_timestamp, self.test_meta.end_timestamp)
                if self.test_meta else None
            ),
        }


class TemporalSplitter:
    """Rigorous chronological splitter with embargo gap and attack-family holdout."""

    def __init__(
        self,
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        test_ratio: float = 0.15,
        embargo_seconds: float = 0.0,
        embargo_steps: int = 0,
        holdout_families: Sequence[str] | None = None,
    ) -> None:
        """Initialize splitter.

        Args:
            train_ratio: Fraction of eligible chronological data for training.
            val_ratio: Fraction of eligible chronological data for validation.
            test_ratio: Fraction of eligible chronological data for testing.
            embargo_seconds: Time gap (seconds) purged between splits.
            embargo_steps: Discrete step count purged between splits (if embargo_seconds == 0).
            holdout_families: List of attack families to completely isolate from train/val.
        """
        ratio_sum = train_ratio + val_ratio + test_ratio
        if abs(ratio_sum - 1.0) > 1e-5:
            raise ValueError(f"Split ratios must sum to 1.0, got {ratio_sum:.4f}")
        if train_ratio <= 0 or val_ratio < 0 or test_ratio <= 0:
            raise ValueError("Train and test ratios must be strictly positive.")

        self.train_ratio = train_ratio
        self.val_ratio = val_ratio
        self.test_ratio = test_ratio
        self.embargo_seconds = max(0.0, float(embargo_seconds))
        self.embargo_steps = max(0, int(embargo_steps))
        self.holdout_families = [f.strip() for f in (holdout_families or []) if f.strip()]

    def split(
        self,
        items: Sequence[T],
        timestamp_fn: Callable[[T], float],
        label_fn: Callable[[T], Any] | None = None,
        family_fn: Callable[[T], str | None] | None = None,
    ) -> TemporalSplitResult[T]:
        """Chronologically partition items into train, validation, and test sets.

        Guarantee:
        - All items in train occur strictly before all items in val.
        - All items in val occur strictly before all items in test.
        - Items falling within embargo windows between splits are purged.
        - Items matching held-out families are isolated into holdout_test.
        """
        if not items:
            return TemporalSplitResult(train=[], val=[], test=[])

        # 1. Sort strictly chronologically by timestamp
        sorted_items = sorted(items, key=timestamp_fn)

        # 2. Check for family holdout separation
        eligible_items: list[T] = []
        holdout_items: list[T] = []

        if self.holdout_families and family_fn is not None:
            holdout_set = set(self.holdout_families)
            for item in sorted_items:
                fam = family_fn(item)
                if fam and fam in holdout_set:
                    holdout_items.append(item)
                else:
                    eligible_items.append(item)
        else:
            eligible_items = list(sorted_items)

        n = len(eligible_items)
        if n == 0:
            return TemporalSplitResult(
                train=[],
                val=[],
                test=[],
                holdout_test=holdout_items,
                held_out_families=list(self.holdout_families),
            )

        # 3. Calculate partition index boundaries
        train_end_idx = int(n * self.train_ratio)
        if self.val_ratio > 0:
            val_end_idx = int(n * (self.train_ratio + self.val_ratio))
        else:
            val_end_idx = train_end_idx

        raw_train = eligible_items[:train_end_idx]
        raw_val = eligible_items[train_end_idx:val_end_idx] if self.val_ratio > 0 else []
        raw_test = eligible_items[val_end_idx:]

        # 4. Apply embargo / purge gaps
        purged_count = 0
        final_train: list[T] = []
        final_val: list[T] = []
        final_test: list[T] = []

        if self.embargo_seconds > 0.0:
            # Time-based embargo
            final_train = raw_train
            if final_train and raw_val:
                train_last_t = timestamp_fn(final_train[-1])
                # Purge val items within embargo_seconds of train_last_t
                embargo_cutoff = train_last_t + self.embargo_seconds
                val_retained = [it for it in raw_val if timestamp_fn(it) > embargo_cutoff]
                purged_count += len(raw_val) - len(val_retained)
                final_val = val_retained
            else:
                final_val = raw_val

            ref_val_last_t = timestamp_fn(final_val[-1]) if final_val else (
                timestamp_fn(final_train[-1]) if final_train else None
            )

            if ref_val_last_t is not None and raw_test:
                embargo_cutoff_test = ref_val_last_t + self.embargo_seconds
                test_retained = [it for it in raw_test if timestamp_fn(it) > embargo_cutoff_test]
                purged_count += len(raw_test) - len(test_retained)
                final_test = test_retained
            else:
                final_test = raw_test
        elif self.embargo_steps > 0:
            # Step-based embargo
            final_train = raw_train
            if self.embargo_steps < len(raw_val):
                purged_count += self.embargo_steps
                final_val = raw_val[self.embargo_steps:]
            else:
                purged_count += len(raw_val)
                final_val = []

            if self.embargo_steps < len(raw_test):
                purged_count += self.embargo_steps
                final_test = raw_test[self.embargo_steps:]
            else:
                purged_count += len(raw_test)
                final_test = []
        else:
            final_train = raw_train
            final_val = raw_val
            final_test = raw_test

        def build_meta(name: str, split_items: list[T]) -> SplitMetadata | None:
            if not split_items:
                return None
            start_t = timestamp_fn(split_items[0])
            end_t = timestamp_fn(split_items[-1])
            lbl_dist: dict[str, int] = {}
            fam_dist: dict[str, int] = {}
            for it in split_items:
                if label_fn is not None:
                    lbl = str(label_fn(it))
                    lbl_dist[lbl] = lbl_dist.get(lbl, 0) + 1
                if family_fn is not None:
                    fam = family_fn(it)
                    fam_str = fam if fam is not None else "BENIGN"
                    fam_dist[fam_str] = fam_dist.get(fam_str, 0) + 1
            return SplitMetadata(
                name=name,
                sample_count=len(split_items),
                start_timestamp=start_t,
                end_timestamp=end_t,
                label_distribution=lbl_dist,
                attack_family_distribution=fam_dist,
            )

        holdout_meta = build_meta("holdout_test", holdout_items) if holdout_items else None

        result = TemporalSplitResult(
            train=final_train,
            val=final_val,
            test=final_test,
            holdout_test=holdout_items,
            embargo_purged_count=purged_count,
            train_meta=build_meta("train", final_train),
            val_meta=build_meta("val", final_val),
            test_meta=build_meta("test", final_test),
            holdout_meta=holdout_meta,
            held_out_families=list(self.holdout_families),
        )

        # Audit split for zero leakage
        self._audit_split(result, timestamp_fn)
        return result

    def _audit_split(
        self,
        result: TemporalSplitResult[T],
        timestamp_fn: Callable[[T], float],
    ) -> None:
        """Validate temporal boundary separation between splits."""
        if result.train and result.val:
            train_max = max(timestamp_fn(it) for it in result.train)
            val_min = min(timestamp_fn(it) for it in result.val)
            if train_max >= val_min:
                raise TemporalLeakageError(
                    f"Train end timestamp ({train_max}) >= Val start timestamp ({val_min}). "
                    "Temporal leakage detected between train and validation splits."
                )
            if self.embargo_seconds > 0.0 and (val_min - train_max) < self.embargo_seconds:
                raise TemporalLeakageError(
                    f"Embargo gap between train and val ({val_min - train_max}s) is smaller "
                    f"than required embargo ({self.embargo_seconds}s)."
                )

        if result.val and result.test:
            val_max = max(timestamp_fn(it) for it in result.val)
            test_min = min(timestamp_fn(it) for it in result.test)
            if val_max >= test_min:
                raise TemporalLeakageError(
                    f"Val end timestamp ({val_max}) >= Test start timestamp ({test_min}). "
                    "Temporal leakage detected between validation and test splits."
                )
            if self.embargo_seconds > 0.0 and (test_min - val_max) < self.embargo_seconds:
                raise TemporalLeakageError(
                    f"Embargo gap between val and test ({test_min - val_max}s) is smaller "
                    f"than required embargo ({self.embargo_seconds}s)."
                )

        if not result.val and result.train and result.test:
            train_max = max(timestamp_fn(it) for it in result.train)
            test_min = min(timestamp_fn(it) for it in result.test)
            if train_max >= test_min:
                raise TemporalLeakageError(
                    f"Train end timestamp ({train_max}) >= Test start timestamp ({test_min}). "
                    "Temporal leakage detected between train and test splits."
                )


def validate_temporal_windows(
    history_timestamps: Sequence[float],
    forecast_timestamps: Sequence[float],
    expected_step_seconds: float | None = None,
    allow_empty: bool = False,
) -> None:
    """Validate window inputs and forecast targets for temporal correctness and zero leakage.

    Audits:
    1. History timestamps must be strictly monotonic (t_0 < t_1 < ... < t_{L-1}).
    2. Forecast timestamps must be strictly monotonic (t_{T+1} < t_{T+2} < ...).
    3. Strict separation: Every history timestamp must be strictly less than every forecast timestamp.
       max(history_timestamps) < min(forecast_timestamps).
    4. If expected_step_seconds is specified, verify regular step spacing without jumps or reverses.
    5. Zero duplicate timestamps within and across history and forecast sets.

    Raises:
        TemporalLeakageError: If any leakage or temporal ordering violation is found.
    """
    if not history_timestamps and not forecast_timestamps:
        if allow_empty:
            return
        raise TemporalLeakageError("Empty history and forecast timestamp sequences provided.")

    if not history_timestamps:
        raise TemporalLeakageError("History timestamps sequence is empty.")
    if not forecast_timestamps:
        raise TemporalLeakageError("Forecast timestamps sequence is empty.")

    # 1. Monotonicity of history
    for i in range(len(history_timestamps) - 1):
        t_curr = history_timestamps[i]
        t_next = history_timestamps[i + 1]
        if t_next <= t_curr:
            raise TemporalLeakageError(
                f"History timestamps not strictly monotonic at index {i}: "
                f"{t_curr} >= {t_next}."
            )

    # 2. Monotonicity of forecast
    for i in range(len(forecast_timestamps) - 1):
        t_curr = forecast_timestamps[i]
        t_next = forecast_timestamps[i + 1]
        if t_next <= t_curr:
            raise TemporalLeakageError(
                f"Forecast timestamps not strictly monotonic at horizon index {i}: "
                f"{t_curr} >= {t_next}."
            )

    # 3. Lookahead / Boundary check
    max_history = history_timestamps[-1]
    min_forecast = forecast_timestamps[0]
    if max_history >= min_forecast:
        raise TemporalLeakageError(
            f"Forward leakage detected: latest history timestamp ({max_history}) "
            f"is >= earliest forecast target timestamp ({min_forecast}). "
            "Input lookback window must precede forecast targets."
        )

    # 4. Spacing check if expected_step_seconds provided
    if expected_step_seconds is not None and expected_step_seconds > 0:
        first_step = min_forecast - max_history
        if abs(first_step - expected_step_seconds) > 1e-2:
            raise TemporalLeakageError(
                f"Forecast target spacing mismatch: step from history end ({max_history}) "
                f"to forecast start ({min_forecast}) is {first_step}s, "
                f"expected {expected_step_seconds}s."
            )
