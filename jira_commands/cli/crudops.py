#!/usr/bin/env python3
#
# interact with jira
#
# Author: Joe Block <jblock@zscaler.com>
# License: Apache 2.0
# Copyright 2022-2023, ZScaler Inc.

import json
import logging
import sys

from jira_commands.cli.common import baseCLIParser, parseTicketCLI, ticketCreationParser
from jira_commands.jira import JiraTool, loadJiraSettings, makeIssueData


def parseTicketAssignCLI():
    """
    Command line options for assigning a ticket
    """
    parser = parseTicketCLI(description="Assign a JIRA ticket to someone")
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


def parseTicketCommentCLI(description: str = "Comment on a JIRA ticket"):
    """
    Command line options for commmenting on a ticket
    """
    parser = parseTicketCLI(description=description)
    parser.add_argument(
        "--comment",
        type=str,
        required=True,
        help="Comment to add to the specified ticket, It only supports very limited formatting - _italic_ and *bold* work, but `code` doesn't.",
    )
    cli = parser.parse_args()
    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cli.log_level.upper())
    return cli


def parseTicketCloseCLI(description="Close a JIRA ticket"):
    """
    Command line options for closing a ticket
    """
    parser = parseTicketCLI(description=description)
    parser.add_argument(
        "--comment",
        type=str,
        help="Comment to add to the specified ticket, It only supports very limited formatting - _italic_ and *bold* work, but `code` doesn't.",
    )
    cli = parser.parse_args()
    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cli.log_level.upper())
    return cli


def parseTicketInspectionCLI(
    description: str = "Vivisect a JIRA ticket so we can determine which custom fields map to which data keys",
):
    """
    Command line options for ticket inspectors
    """
    parser = parseTicketCLI(description=description)
    cli = parser.parse_args()
    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cli.log_level.upper())
    return cli


def parseCreateTicketCLI(description: str = "Create a JIRA ticket"):
    """
    Parse the command line options
    """
    parser = ticketCreationParser(description=description)
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


def parseGetTransitionsCLI(
    description: str = "See all transitions available on a JIRA ticket",
):
    """
    Parse the command line options for transition list tool
    """
    parser = parseTicketCLI(description=description)

    cli = parser.parse_args()
    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.debug("Set log level to %s", cli.log_level.upper())
    return cli


def parseTicketLinkCLI(description: str = "Link two JIRA tickets"):
    """
    Command line options for linking two tickets
    """
    parser = parseTicketCLI(description=description)
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


def parseTransitionToCLI(
    description: str = "See all transitions available on a JIRA ticket",
):
    """
    Parse the command line options for transition set tool
    """
    parser = parseTicketCLI(description=description)
    parser.add_argument(
        "--transition-to", help="Transition a ticket to a named state", type=str
    )

    cli = parser.parse_args()
    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.debug("Set log level to %s", cli.log_level.upper())
    return cli


def assignTicket():
    """
    Assign a ticket to someone
    """
    cli = parseTicketAssignCLI()
    logging.debug(f"cli: {cli}")

    settings = loadJiraSettings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    if cli.assignee.lower() == "none":
        jira.unassignTicket(ticket=cli.ticket)
    else:
        jira.assignTicket(ticket=cli.ticket, assignee=cli.assignee)


def commentOnTicket():
    """
    Comment on a ticket
    """
    cli = parseTicketCommentCLI()
    logging.debug(f"cli: {cli}")

    settings = loadJiraSettings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    jira.addComment(ticket=cli.ticket, comment=cli.comment)


def closeTicket():
    """
    Close a ticket
    """
    cli = parseTicketCommentCLI()
    logging.debug(f"cli: {cli}")

    settings = loadJiraSettings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    jira.transitionTicket(ticket=cli.ticket, state="Done", comment=cli.comment)


def createTicket():
    """
    Create a JIRA ticket
    """
    cli = parseCreateTicketCLI()
    logging.debug(f"cli: {cli}")

    settings = loadJiraSettings(path=cli.settings_file, cli=cli)
    issue_data = makeIssueData(cli=cli)

    jira = JiraTool(settings=settings)
    if cli.issue_type == "Sub-task":
        results = jira.createSubtask(issue_data=issue_data, parent=cli.parent)
    else:
        results = jira.createTicket(
            issue_data=issue_data, strict=False, priority=cli.priority
        )
    print(results)
    # return results


def getLinkTypes():
    """
    Get all the link types on a server
    """
    parser = baseCLIParser()
    parser.add_argument("--json", help="Output in JSON format", action="store_true")
    cli = parser.parse_args()

    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.debug("Set log level to %s", cli.log_level.upper())

    settings = loadJiraSettings(path=cli.settings_file, cli=cli)

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
    """
    Link two tickets
    """
    cli = parseTicketLinkCLI()
    logging.debug(f"cli: {cli}")

    settings = loadJiraSettings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    results = jira.linkIssues(
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
    """
    Get all the priorities on a server
    """
    parser = baseCLIParser(
        description="Get list of priorities on a server and their IDs"
    )
    parser.add_argument("--json", help="Output in JSON format", action="store_true")
    cli = parser.parse_args()

    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.debug("Set log level to %s", cli.log_level.upper())

    settings = loadJiraSettings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    priority_data = jira.getPriorityDict()

    if cli.json:
        print(json.dumps({"priorities": priority_data}, indent=2))
    else:
        print(f"Issue Priorities: {priority_data}")


def getTransitions():
    """
    Print all the available transitions on a given ticket
    """
    cli = parseGetTransitionsCLI()
    logging.debug(f"cli: {cli}")

    settings = loadJiraSettings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    print(jira.ticketTransitions(ticket=cli.ticket))


def transitionTo():
    """
    Transition a given ticket to a specified state
    """
    cli = parseTransitionToCLI()
    logging.debug(f"cli: {cli}")

    settings = loadJiraSettings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    print(jira.transitionTicket(ticket=cli.ticket, state=cli.transition_to))


if __name__ == "__main__":
    raise RuntimeError("This file should not be run directly, import functions from it")
