#!/usr/bin/env python3
#
# Vivisect a jira ticket so we can figure out the data structure and custom
# fields for a specific ticket type.
#
# Author: Joe Block <jblock@zscaler.com>
# License: Apache 2.0
# Copyright 2022, ZScaler Inc.

import logging

from jira_commands.cli.common import parseTicketCLI
from jira_commands.jira import JiraTool, loadJiraSettings


def parseVivisectCLI():
    """
    Parse the command line options
    """
    parser = parseTicketCLI(
        description="Vivisect a JIRA ticket so we can determine which custom fields map to which data keys"
    )

    cliArgs = parser.parse_args()
    loglevel = getattr(logging, cliArgs.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cliArgs.log_level.upper())
    return cliArgs


def vivisect():
    """
    Vivisect a ticket so we can figure out what key names the various custom
    fields have, what transitions are available, etc.
    """
    cli = parseVivisectCLI()
    logging.debug(f"cli: {cli}")

    settings = loadJiraSettings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    jira.vivisect(ticket_id=cli.ticket)


if __name__ == "__main__":
    vivisect()
