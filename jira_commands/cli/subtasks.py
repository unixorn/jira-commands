#
# Get the subtasks of a ticket
#
# Author: Joe Block <jblock@zscaler.com>
# License: Apache 2.0
# Copyright 2023, ZScaler Inc.

import logging

from jira_commands.cli.common import parse_ticket_cli, stdin_to_string
from jira_commands.jira import JiraTool, load_jira_settings
from jira_commands.cli.crudops import (
    parse_ticket_assign_cli,
    parse_ticket_comment_cli,
    parse_transition_to_cli,
)


def parse_subtasks_cli(description="List subtasks for an issue"):
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


# Entrypoints


def assign_subtasks():
    """
    Assign all of an issue's subtasks to the same user
    """
    cli = parse_ticket_assign_cli(
        description="Assign all of an issue's subtasks to the same user"
    )
    logging.debug(f"cli: {cli}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    subtasks_l = jira.list_issue_subtasks(ticket=cli.ticket)
    for subtask in subtasks_l:
        jira.assign_ticket(ticket=subtask, assignee=cli.assignee)


def close_subtasks():
    """
    Close a ticket
    """
    cli = parse_ticket_comment_cli(description="Close all of an issue's subtasks")
    logging.debug(f"cli: {cli}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    subtasks_l = jira.list_issue_subtasks(ticket=cli.ticket)
    for subtask in subtasks_l:
        jira.transition_ticket(ticket=subtask, state="Done", comment=cli.comment)


def comment_on_subtasks():
    """
    Add an identical comment to all of an issue's subtasks
    """
    cli = parse_ticket_comment_cli(
        description="Add an identical comment to all of an issue's subtasks"
    )
    logging.debug(f"cli: {cli}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    subtasks_l = jira.list_issue_subtasks(ticket=cli.ticket)
    if cli.stdin_comment:
        stdin_comment = stdin_to_string()
    for subtask in subtasks_l:
        jira.add_comment(ticket=subtask, comment=cli.comment)
        if stdin_comment:
            jira.add_comment(ticket=cli.ticket, comment=stdin_comment)


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


def transition_subtasks(
    description="Transition all subtasks of an issue to a specific state",
):
    """
    Transition all subtasks of an issue to a given state
    """
    cli = parse_transition_to_cli(description=description)
    logging.debug(f"cli: {cli}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    subtasks_l = jira.list_issue_subtasks(ticket=cli.ticket)
    for subtask in subtasks_l:
        jira.transition_ticket(
            ticket=subtask, state=cli.transition_to, comment=cli.comment
        )
