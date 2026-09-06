#!/usr/bin/env python3
"""Checker entrypoint. Loads your test cases, then runs the harness.

You shouldn't need to edit this — add checks in checks.py. Importing
checks first registers every @check function on the (single, by-name)
checker module before we run it.
"""
import checks  # noqa: F401 — import side-effect registers the @check functions
import checker

checker.main()