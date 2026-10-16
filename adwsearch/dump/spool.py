# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Hexboi (https://github.com/Hexboi)

"""Disk-backed JSON collections with atomic final publication."""

import json
import os
import tempfile
from contextlib import AbstractContextManager, ExitStack

from adwsearch.output.atomic import atomic_text_file

KINDS = {"users": "Users", "computers": "Computers", "groups": "Groups",
         "ous": "OUs", "gpos": "GPOs", "containers": "Containers", "domains": "Domains"}


class JsonSpool(AbstractContextManager):
    """Replayable collection keeping only a single node in memory."""

    def __init__(self, directory):
        self._stream = tempfile.TemporaryFile(mode="w+t", encoding="utf-8", dir=directory)
        self._count = 0

    def append(self, node):
        self._stream.seek(0, os.SEEK_END)
        self._stream.write(json.dumps(node, ensure_ascii=False, default=str) + "\n")
        self._count += 1

    def __len__(self):
        return self._count

    def __iter__(self):
        self._stream.flush()
        self._stream.seek(0)
        for line in self._stream:
            yield json.loads(line)

    def publish(self, path, meta):
        with atomic_text_file(path) as stream:
            stream.write('{"data":[')
            for index, node in enumerate(self):
                if index:
                    stream.write(",")
                json.dump(node, stream, ensure_ascii=False, default=str)
            stream.write('],"meta":')
            json.dump(meta, stream, default=str)
            stream.write("}\n")

    def __exit__(self, *exc):
        self._stream.close()


class JsonBucketSpool(AbstractContextManager):
    def __init__(self, outdir: str):
        self.outdir = outdir
        self._stack = ExitStack()
        try:
            self._buckets = {kind: self._stack.enter_context(JsonSpool(outdir)) for kind in KINDS}
        except BaseException:
            self._stack.close()
            raise

    def append(self, kind: str, node: dict) -> None:
        self._buckets[kind].append(node)

    def publish(self, header: str) -> dict[str, int]:
        # Stage every bucket before replacing any existing final file.
        with tempfile.TemporaryDirectory(prefix=".adwsearch-", dir=self.outdir) as stage:
            for kind, spool in self._buckets.items():
                spool.publish(os.path.join(stage, f"{header}_output{KINDS[kind]}.json"),
                              {"count": len(spool), "type": kind, "methods": 0, "version": 5})
            for filename in os.listdir(stage):
                os.replace(os.path.join(stage, filename), os.path.join(self.outdir, filename))
        return {kind: len(spool) for kind, spool in self._buckets.items()}

    def __bool__(self):
        return any(len(s) for s in self._buckets.values())

    def __exit__(self, *exc):
        self._stack.close()
