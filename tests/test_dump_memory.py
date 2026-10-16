# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

import tracemalloc

import pytest

from adwsearch.dump.spool import JsonBucketSpool


@pytest.mark.performance
def test_bucket_memory_does_not_scale_with_node_payloads(tmp_path):
    def peak(count, directory):
        directory.mkdir()
        tracemalloc.start()
        with JsonBucketSpool(str(directory)) as spool:
            for index in range(count):
                spool.append("users", {"ObjectIdentifier": str(index), "description": "x" * 512})
            counts = spool.publish("full")
            assert counts["users"] == count
        _, value = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return value
    small = peak(10_000, tmp_path / "small")
    large = peak(100_000, tmp_path / "large")
    assert large <= small + 16 * 1024 * 1024
