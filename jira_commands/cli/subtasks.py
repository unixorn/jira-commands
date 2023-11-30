#
# Get the subtasks of a ticket
#
# Author: Joe Block <jblock@zscaler.com>
# License: Apache 2.0
# Copyright 2023, ZScaler Inc.

import logging
import pprint

from jira_commands.cli.common import parse_ticket_cli
from jira_commands.jira import JiraTool, load_jira_settings


def parse_subtasks_cli(description="List subtasks for a ticket"):
    """
    Parse the command line options for jc-ticket-subtasks
    """
    parser = parse_ticket_cli(description=description)
    cli = parser.parse_args()

    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cli.log_level.upper())

    return cli


def list_subtasks():
    """
    List a ticket's subtasks
    """
    cli = parse_subtasks_cli()
    logging.debug(f"cli: {cli}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    subtasks = jira.list_issue_subtasks(ticket=cli.ticket)
    # print(f"  {pprint.pformat(subtasks, indent=2)}")
    for s in subtasks:
        print(f"{s} ", end="")
