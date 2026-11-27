#!/usr/bin/env python3
# Copyright 2026 lazyeel (https://github.com/lazyeel)
# SPDX-License-Identifier: Apache-2.0

import tempfile
import unittest

from tools.trace_slice import Slicer


class TraceSliceBoundaryTests(unittest.TestCase):
    def test_record_zero_is_an_external_seed_not_a_negative_seek(self):
        with tempfile.NamedTemporaryFile() as trace:
            slicer = Slicer(trace.name, 0)
            self.assertIsNone(slicer.last_writer(0, 0))


if __name__ == "__main__":
    unittest.main()
