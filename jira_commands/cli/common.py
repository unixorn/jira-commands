#!/usr/bin/env python3
#
# Author: Joe Block <jblock@zscaler.com>
# License: Apache 2.0
# Copyright 2022, ZScaler Inc.

import argparse
import os
import sys

from thelogrus.fileops import readableFile


def baseCLIParser(description: str = None):
    """
    Create the base argument parser that we build on for individual scripts
    """
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-d", "--debug", help="Enable debug mode", action="store_true")
    parser.add_argument(
        "--log-level",
        "--logging",
        "-l",
        type=str.upper,
        help="set log level",
        choices=["DEBUG", "INFO", "ERROR", "WARNING", "CRITICAL"],
        default="INFO",
    )

    # We have different default settings file paths based on whether we're
    # running in a container, on a server, or on a laptop.
    settingsFileDefault = "/config/jira.yaml"
    settingsFileCandidates = [settingsFileDefault, "/etc/zscaler/jira/jira.yaml"]
    if "HOME" in os.environ:
        settingsFileCandidates.append(f"{os.environ.get('HOME')}/.zscaler/jira.yaml")
    for candidate in settingsFileCandidates:
        if readableFile(candidate):
            settingsFileDefault = candidate
    parser.add_argument(
        "--settings-file", "--settings", type=str, default=settingsFileDefault
    )
    parser.add_argument("--server", type=str)

    parser.add_argument(
        "--username",
        type=str,
        help="What username to use with JIRA. This overrides any setting in the settings file.",
    )
    parser.add_argument(
        "--password",
        type=str,
        help="What username to use with JIRA. This overrides any setting in the settings file.",
    )

    return parser


def parseTicketCLI(description: str):
    """
    Parse the command line options and return the ticket id
    """
    parser = baseCLIParser(description=description)

    parser.add_argument("--ticket", "-t", type=str, required=True)
    return parser


def ticketCreationParser(description: str):
    """
    Create the base ticket creation parser
    """
    parser = baseCLIParser(description="Create a JIRA ticket")

    # Collect issue attributes
    parser.add_argument("--description", help="Ticket description", type=str)

    parser.add_argument(
        "--json", "--json-data", help="Custom ticket data as a JSON string", type=str
    )
    parser.add_argument("--label", help="Ticket label", type=str)
    # JIRA is case sensitive about issue IDs. If we ever have a JIRA project that
    # is not all-caps, this will break.
    parser.add_argument(
        "--parent",
        help="Ticket parent - required when creating subtasks",
        type=str.upper,
    )
    parser.add_argument(
        "--priority",
        help="Set priority for the new ticket. Use 'jc get priorites' to find a list of available ticket priorities.",
        type=str,
    )
    parser.add_argument(
        "--project",
        help="What JIRA project to create the new ticket in",
        type=str,
        default="SYSENG",
    )
    parser.add_argument("--summary", help="Ticket summary", type=str)

    # JIRA is picky about capitalization, so enforce valid spellings
    baseTicketTypes = (["Bug", "Epic", "Improvement", "Sub-task", "Task"],)
    parser.add_argument(
        "--issue-type",
        type=str,
        help=f"set issue type (try {baseTicketTypes})",
        default="Task",
    )
    return parser


if __name__ == "__main__":
    print("Don't run this directly, import functions from it")
    sys.exit(13)
