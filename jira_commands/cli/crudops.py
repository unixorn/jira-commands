#!/usr/bin/env python3
#
# interact with jira
#
# Author: Joe Block <jblock@zscaler.com>
# License: Apache 2.0
# Copyright 2022, ZScaler Inc.

import logging
import sys

from jira_commands.cli.common import parseTicketCLI, ticketCreationParser
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


def parseTicketCommentCLI():
    """
    Command line options for commmenting on a ticket
    """
    parser = parseTicketCLI(description="Comment on a JIRA ticket")
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


def parseTicketCloseCLI():
    """
    Command line options for closing a ticket
    """
    parser = parseTicketCLI(description="Close a JIRA ticket")
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


def parseTicketInspectionCLI():
    """
    Command line options for ticket inspectors
    """
    parser = parseTicketCLI(
        description="Vivisect a JIRA ticket so we can determine which custom fields map to which data keys"
    )
    cli = parser.parse_args()
    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cli.log_level.upper())
    return cli


def parseCreateTicketCLI():
    """
    Parse the command line options
    """
    parser = ticketCreationParser(description="Create a JIRA ticket")
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


def parseGetTransitionsCLI():
    """
    Parse the command line options for transition list tool
    """
    parser = parseTicketCLI(
        description="See all transitions available on a JIRA ticket"
    )

    cliArgs = parser.parse_args()
    loglevel = getattr(logging, cliArgs.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cliArgs.log_level.upper())
    return cliArgs


def parseTransitionToCLI():
    """
    Parse the command line options for transition set tool
    """
    parser = parseTicketCLI(
        description="See all transitions available on a JIRA ticket"
    )
    parser.add_argument(
        "--transition-to", help="Transition a ticket to a named state", type=str
    )

    cliArgs = parser.parse_args()
    loglevel = getattr(logging, cliArgs.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cliArgs.log_level.upper())
    return cliArgs


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
    Main program driver
    """
    cli = parseCreateTicketCLI()
    logging.debug(f"cli: {cli}")

    settings = loadJiraSettings(path=cli.settings_file, cli=cli)
    issue_data = makeIssueData(cli=cli)

    jira = JiraTool(settings=settings)
    if cli.issue_type == "Sub-task":
        logging.info(jira.createSubtask(issue_data=issue_data, parent=cli.parent))
    else:
        logging.info(jira.createTicket(issue_data=issue_data, strict=False))


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
