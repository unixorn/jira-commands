#
# interact with jira
#
# Author: Joe Block <jblock@zscaler.com>
# License: Apache 2.0
# Copyright 2022-2023, ZScaler Inc.

import json
import logging
import os
import sys

from jira_commands import __version__ as cli_version
from jira_commands.cli.common import (
    base_cli_parser,
    parse_ticket_cli,
    stdin_to_string,
    ticket_creation_parser,
)
from jira_commands.jira import JiraTool, load_jira_settings, make_issue_data


def default_comment() -> str:
    username = os.environ.get("USER", "docker container")
    comment = "Updated with jc v" + cli_version + " by " + username
    logging.debug(f"Default comment: {comment}")
    return comment


# CLI parsers


def parse_ticket_assign_cli(description: str = "Assign a JIRA ticket to someone"):
    """
    Parses the command line options for assigning a ticket and
    initializes logging.

    Returns:
        An argparse CLI object
    """
    parser = parse_ticket_cli(description=description)
    parser.add_argument(
        "--assignee",
        type=str,
        required=True,
        help="Username to assign ticket to. Specify None if you want to unassign the ticket",
    )
    cli = parser.parse_args()
    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cli.log_level.upper())
    return cli


def parse_ticket_comment_cli(description: str = "Comment on a JIRA ticket"):
    """
    Parse command line options for commenting on a ticket and initializes
    logging.

    Returns:
        An argparse CLI object
    """
    parser = parse_ticket_cli(description=description)
    parser.add_argument(
        "--comment",
        type=str,
        default=default_comment(),
        help="Comment to add to the specified ticket. It only supports very "
        "limited formatting - _italic_ and *bold* work, but `code` doesn't."
        " Default: " + default_comment(),
    )
    parser.add_argument(
        "--stdin-comment",
        "--stdin",
        help="Read a comment from STDIN",
        action="store_true",
    )
    cli = parser.parse_args()
    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cli.log_level.upper())
    return cli


def parse_ticket_close_cli(description="Close a JIRA ticket"):
    """
    Parses command line options for closing a ticket and initializes logging.

    Returns:
        An argparse CLI object
    """
    parser = parse_ticket_cli(description=description)
    parser.add_argument(
        "--comment",
        type=str,
        default=default_comment(),
        help="Comment to add to the specified ticket. It only supports very "
        "limited formatting - _italic_ and *bold* work, but `code` doesn't."
        " Defaults: " + default_comment(),
    )
    cli = parser.parse_args()
    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cli.log_level.upper())
    return cli


def parseTicketInspectionCLI():
    logging.warning(
        "parseTicketInspectionCLI() is deprecated and will be removed. Use parse_ticket_inspection_cli() instead"
    )
    parse_ticket_inspection_cli()


def parse_ticket_inspection_cli(
    description: str = "Vivisect a JIRA ticket so we can determine which "
    "custom fields map to which data keys",
):
    """
    Parses command line options for ticket inspectors and initializes logging.

    Returns:
        An argparse CLI object
    """
    parser = parse_ticket_cli(description=description)
    cli = parser.parse_args()
    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cli.log_level.upper())
    return cli


def parse_create_ticket_cli(description: str = "Create a JIRA ticket"):
    """
    Parse the command line options
    """
    parser = ticket_creation_parser(description=description)
    cli = parser.parse_args()

    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cli.log_level.upper())

    # Validity checks
    if cli.issue_type == "Sub-task":
        if not cli.parent:
            logging.error(
                "You must specify a parent with --parent when you are creating a subtask"
            )
            sys.exit(13)
    return cli


def parse_get_transitions_cli(
    description: str = "See all transitions available on a JIRA ticket",
):
    """
    Parse the command line options for transition list tool
    """
    parser = parse_ticket_cli(description=description)

    cli = parser.parse_args()
    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.debug("Set log level to %s", cli.log_level.upper())
    return cli


def parse_ticket_link_cli(description: str = "Link two JIRA tickets"):
    """
    Command line options for linking two tickets
    """
    parser = parse_ticket_cli(description=description)
    parser.add_argument(
        "--target",
        type=str,
        required=True,
        help="Target ticket",
    )

    link_types = [
        "Blocks",
        "Depends",
        "Bugs" "Clones",
    ]
    parser.add_argument(
        "--link-type",
        type=str,
        required=True,
        help=f"Link type. Case matters. Consider {link_types} as options, "
        "though your server may have other types too. 'jc get link types' "
        "will show all the link types on your JIRA server",
    )
    cli = parser.parse_args()
    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.debug("Set log level to %s", cli.log_level.upper())
    return cli


def parse_transition_to_cli(
    description: str = "See all transitions available on a JIRA ticket",
):
    """
    Parse the command line options for transition set tool
    """
    parser = parse_ticket_cli(description=description)
    parser.add_argument(
        "--comment",
        type=str,
        default=default_comment(),
        help="Comment to add to the specified ticket. It only supports very "
        "limited formatting - _italic_ and *bold* work, but `code` doesn't."
        " Default: " + default_comment(),
    )
    parser.add_argument(
        "--transition-to",
        help="Transition a ticket to a named state",
        type=str,
        default="Done",
    )
    cli = parser.parse_args()
    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.debug("Set log level to %s", cli.log_level.upper())
    return cli


# Entrypoints


def assign_ticket():
    """
    Assign a ticket to someone
    """
    cli = parse_ticket_assign_cli()
    logging.debug(f"cli: {cli}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    if cli.assignee.lower() == "none":
        jira.unassign_ticket(ticket=cli.ticket)
    else:
        jira.assign_ticket(ticket=cli.ticket, assignee=cli.assignee)


def close_ticket():
    """
    Close a ticket
    """
    cli = parse_ticket_comment_cli()
    logging.debug(f"cli: {cli}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    jira.transition_ticket(ticket=cli.ticket, state="Done", comment=cli.comment)


def commentOnTicket():
    logging.warning(
        "commentOnTicket is deprecated and will be removed, use comment_on_ticket instead"
    )
    comment_on_ticket()


def comment_on_ticket():
    """
    Comment on a ticket
    """
    cli = parse_ticket_comment_cli()
    logging.debug(f"cli: {cli}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    jira.add_comment(ticket=cli.ticket, comment=cli.comment)
    if cli.stdin_comment:
        stdin_comment = stdin_to_string()
        if stdin_comment:
            jira.add_comment(ticket=cli.ticket, comment=stdin_comment)


def createTicket():
    logging.warning(
        "createTicket is deprecated and will be removed, use create_ticket instead"
    )
    create_ticket()


def create_ticket():
    """
    Create a JIRA ticket
    """
    cli = parse_create_ticket_cli()
    logging.debug(f"cli: {cli}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)
    issue_data = make_issue_data(cli=cli)

    jira = JiraTool(settings=settings)
    if cli.issue_type == "Sub-task":
        results = jira.create_subtask(issue_data=issue_data, parent=cli.parent)
    else:
        results = jira.create_ticket(
            issue_data=issue_data, strict=False, priority=cli.priority
        )
    print(results)
    # return results


def getLinkTypes():
    logging.warning(
        "getLinkTypes is deprecated and will be removed, use get_link_types instead"
    )
    get_link_types()


def get_link_types():
    """
    Get all the link types on a server
    """
    parser = base_cli_parser()
    parser.add_argument("--json", help="Output in JSON format", action="store_true")
    cli = parser.parse_args()

    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.debug("Set log level to %s", cli.log_level.upper())

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)

    link_type_names = []
    for link_type in jira.connection.issue_link_types():
        logging.debug(link_type.name)
        link_type_names.append(link_type.name)
    if cli.json:
        print(json.dumps({"link_types": link_type_names}, indent=2))
    else:
        print(f"Link type names: {link_type_names}")


def linkTickets():
    logging.warning(
        "linkTickets is deprecated and will be removed, use link_tickets instead"
    )


def link_tickets():
    """
    Link two tickets
    """
    cli = parse_ticket_link_cli()
    logging.debug(f"cli: {cli}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    results = jira.link_issues(
        source=cli.ticket, target=cli.target, link_type=cli.link_type
    )
    logging.debug(results)
    if results:
        print(f"({cli.link_type}) link created between {cli.ticket} and {cli.target}")
    else:
        print(
            f"Could not create ({cli.link_type})Link between {cli.ticket} and {cli.target}"
        )
    print(results)


def getPriorities():
    logging.warning(
        "getPriorities is deprecated and will be removed, use get_priorities instead"
    )


def get_priorities():
    """
    Get all the priorities on a server
    """
    parser = base_cli_parser(
        description="Get list of priorities on a server and their IDs"
    )
    parser.add_argument("--json", help="Output in JSON format", action="store_true")
    cli = parser.parse_args()

    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.debug("Set log level to %s", cli.log_level.upper())

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    priority_data = jira.get_priority_dict()

    if cli.json:
        print(json.dumps({"priorities": priority_data}, indent=2))
    else:
        print(f"Issue Priorities: {priority_data}")


def getTransitions():
    logging.warning(
        "getTransitions is deprecated and will be removed, use get_transitions instead"
    )


def get_transitions():
    """
    Print all the available transitions on a given ticket
    """
    cli = parse_get_transitions_cli()
    logging.debug(f"cli: {cli}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    print(jira.ticket_transitions(ticket=cli.ticket))


def transitionTo():
    logging.warning(
        "transitionTo is deprecated and will be removed, use transition_to instead"
    )


def transition_to():
    """
    Transition a given ticket to a specified state
    """
    cli = parse_transition_to_cli()
    logging.debug(f"cli: {cli}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    print(jira.transition_ticket(ticket=cli.ticket, state=cli.transition_to))


if __name__ == "__main__":
    raise RuntimeError("This file should not be run directly, import functions from it")
