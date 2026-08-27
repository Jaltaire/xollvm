"""Feature gates: MBA-advanced and opaque-predicate families."""

from __future__ import annotations

from ._common import Registry, ann_extra


def register(reg: Registry, **_opts) -> None:
    reg.add(
        name="rt_mba_advanced", passes=["mba"],
        ann_override=ann_extra("mba_advanced"),
        gates=["mba_advanced"], category="feature",
    )
    reg.add(
        name="rt_opaque_families", passes=["flattening", "bcf"],
        ann_override=ann_extra("opaque_families"),
        extra_opts=["--obf-ir-budget-multiplier=100"],
        gates=["opaque_families"], category="feature",
    )
