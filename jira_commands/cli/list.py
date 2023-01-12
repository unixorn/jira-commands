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


def parseListCLI(description="List JIRA tickets in a project"):
    """
    Parse the command line options
    """
    parser = baseCLIParser(description=description)
    parser.add_argument("--project", "-p", type=str, default="SYSENG")

    cli = parser.parse_args()
    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cli.log_level.upper())
    return cli


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
