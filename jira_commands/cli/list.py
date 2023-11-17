#
# interact with jira
#
# Author: Joe Block <jblock@zscaler.com>
# License: Apache 2.0
# Copyright 2022-2023, ZScaler Inc.

import logging

from jira_commands.cli.common import base_cli_parser
from jira_commands.jira import JiraTool, load_jira_settings


def parseListCLI(description="List JIRA tickets in a project"):
    """
    Parse the command line options for the ticket list script and
    initialize logging.
    """
    parser = base_cli_parser(description=description)
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

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    jira.list_tickets(project="SYSENG")


if __name__ == "__main__":
    listTickets()
