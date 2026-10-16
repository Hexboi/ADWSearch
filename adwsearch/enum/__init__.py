# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Enumeration presets: one-shot ADWS recipes for common recon tasks.

Public API: ``PRESETS`` — mapping from preset name to :class:`Preset` instance.
Each preset's ``run(client, args) -> Iterator[AdObject]`` is the single entry point;
the CLI dispatches through it while keeping the writer / --outfile / --raw paths
untouched.
"""

from adwsearch.enum.presets import PRESETS, Preset

__all__ = ["PRESETS", "Preset"]
