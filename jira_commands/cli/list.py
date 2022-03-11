#!/usr/bin/env python3
#
# interact with jira
#
# Author: Joe Block <jblock@zscaler.com>
# License: Apache 2.0
# Copyright 2022, ZScaler Inc.

import logging

from jira_commands.cli.common import baseCLIParser
from jira_commands.jira import JiraTool, loadJiraSettings


def parseListCLI():
    """
    Parse the command line options
    """
    parser = baseCLIParser(description="List JIRA tickets in a project")

    parser.add_argument("--project", "-p", type=str, default="SYSENG")

    cliArgs = parser.parse_args()
    loglevel = getattr(logging, cliArgs.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cliArgs.log_level.upper())
    return cliArgs


def listTickets():
    """
    List tickets in a project
    """
    cli = parseListCLI()
    logging.debug(f"cli: {cli}")

    settings = loadJiraSettings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    jira.listTickets(project="SYSENG")


if __name__ == "__main__":
    listTickets()
