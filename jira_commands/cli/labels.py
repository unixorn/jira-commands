#
# Label operations
#
# Author: Joe Block <jblock@zscaler.com>
# License: Apache 2.0
# Copyright 2024, ZScaler Inc.
import json
import logging

from jira_commands.cli.common import parse_ticket_cli
from jira_commands.jira import JiraTool, load_jira_settings


def add_label_parser(description="Add labels to an issue"):
    """
    Add a label to a ticket
    """
    parser = parse_ticket_cli(description=description)
    parser.add_argument(
        "--label",
        type=str,
        required=True,
        help="label to add to the target issue",
    )
    parser.add_argument(
        "--include-subtasks", help="Include subtasks", action="store_true"
    )
    return parser


def get_labels_parser(description="Get the labels on an issue"):
    """
    Add a label to a ticket
    """
    parser = parse_ticket_cli(description=description)
    parser.add_argument(
        "--include-subtasks",
        help="Also alter the ticket's subtasks",
        action="store_true",
    )
    parser.add_argument("--json", help="use json for output", action="store_true")
    return parser


def remove_label_parser(description="Delete labels from an issue"):
    """
    Delete a label from a ticket
    """
    parser = parse_ticket_cli(description=description)
    parser.add_argument(
        "--delete-label",
        type=str,
        required=True,
        help="label to remove from the target issue",
    )
    parser.add_argument(
        "--include-subtasks",
        help="Also alter the ticket's subtasks",
        action="store_true",
    )
    return parser


def cli_setup(parser=None):
    cli = parser.parse_args()

    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cli.log_level.upper())
    return cli


# Entrypoints


def add_label():
    """
    Add a label to a ticket and optionally its subtasks
    """
    parser = add_label_parser(
        description="Add a label or labels to an issue and optionally its subtasks"
    )
    cli = cli_setup(parser=parser)
    logging.debug(f"cli: {cli}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)

    jira.add_issue_label(ticket=cli.ticket, labels=cli.label)
    if cli.include_subtasks:
        subtasks_l = jira.list_issue_subtasks(ticket=cli.ticket)
        for subtask in subtasks_l:
            jira.add_issue_label(ticket=subtask, labels=cli.label)


def get_labels():
    """
    Get all the labels on a ticket
    """
    parser = get_labels_parser(description="Show the labels on an issue")
    cli = cli_setup(parser=parser)
    logging.debug(f"cli: {cli}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)

    labels = jira.get_issue_labels(
        ticket=cli.ticket,
    )
    json_results = {cli.ticket: labels}

    if cli.include_subtasks:
        subtasks_l = jira.list_issue_subtasks(ticket=cli.ticket)
        for subtask in subtasks_l:
            subtask_labels = jira.get_issue_labels(ticket=subtask)
            json_results[subtask] = subtask_labels
            if not cli.json:
                print(f"{subtask}:{subtask_labels}")
    if cli.json:
        print(json.dumps(json_results))
    else:
        print(f"{cli.ticket}:{labels}")


def remove_label():
    """
    Add a label to a ticket and optionally its subtasks
    """
    parser = remove_label_parser(
        description="Remove a label or labels from an issue and optionally its subtasks",
    )
    cli = cli_setup(parser=parser)
    logging.debug(f"cli: {cli}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)

    jira.remove_issue_label(ticket=cli.ticket, label=cli.delete_label)
    if cli.include_subtasks:
        subtasks_l = jira.list_issue_subtasks(ticket=cli.ticket)
        for subtask in subtasks_l:
            jira.remove_issue_label(ticket=subtask, label=cli.delete_label)
