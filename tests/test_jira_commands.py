#!/usr/bin/env python3

from jira_commands import __version__


def test_version():
    assert __version__ == "0.1.0"
