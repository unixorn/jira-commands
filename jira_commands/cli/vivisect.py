#!/usr/bin/env python3
#
# Vivisect a jira ticket so we can figure out the data structure and custom
# fields for a specific ticket type.
#
# Author: Joe Block <jblock@zscaler.com>
# License: Apache 2.0
# Copyright 2022, ZScaler Inc.

import json
import logging
import pprint

from jira_commands.cli.common import parseTicketCLI, baseCLIParser
from jira_commands.jira import JiraTool, loadJiraSettings


def dump_all_customfield_allowed_values():
    """
    Dump all the customfield allowed options for a given ticket
    """
    cli = parse_dump_all_customfields_cli()
    logging.debug(f"cli: {cli}")

    settings = loadJiraSettings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    allowed_dict = jira.load_customfield_allowed_values(ticket=cli.ticket)
    print(json.dumps(allowed_dict))


def parse_dump_all_customfields_cli():
    """
    Parse the command line options for jc-ticket-dump-all-customfields
    """
    parser = parseTicketCLI(description="Dump a ticket's metadata")

    cliArgs = parser.parse_args()
    loglevel = getattr(logging, cliArgs.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cliArgs.log_level.upper())
    return cliArgs


def dump_metadata():
    """
    Dump a ticket's metadata
    """
    cli = parse_metadata_cli()
    logging.debug(f"cli: {cli}")

    settings = loadJiraSettings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    metadata = jira.getIssueMetaData(ticket=cli.ticket)
    print(f"  {pprint.pformat(metadata, indent=2)}")


def parse_metadata_cli():
    """
    Parse the command line options for jc-ticket-metadata
    """
    parser = parseTicketCLI(description="Dump a ticket's metadata")

    cliArgs = parser.parse_args()
    loglevel = getattr(logging, cliArgs.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cliArgs.log_level.upper())
    return cliArgs


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


def parseTicketFieldCLI(description: str):
    """
    Parse the command line options and return the ticket id
    """
    parser = baseCLIParser(description=description)

    parser.add_argument("--ticket", "-t", type=str, required=True)
    parser.add_argument("--custom-field", "-c", type=str, required=True)
    return parser


def listAllowedFieldValues():
    cli = parseTicketFieldCLI(
        description="Get the allowed values for a ticket's custom field"
    ).parse_args()

    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cli.log_level.upper())

    logging.debug(f"cli: {cli}")
    logging.debug(f"ticket: {cli.ticket}")
    logging.debug(f"custom_field: {cli.custom_field}")

    settings = loadJiraSettings(path=cli.settings_file, cli=cli)
    jira = JiraTool(settings=settings)
    print(f"Values for {cli.ticket}'s {cli.custom_field}:")
    for allowed in jira.allowedValuesForField(
        ticket=cli.ticket, custom_field=cli.custom_field
    ):
        print(f"  {pprint.pformat(allowed, indent=2)}")


if __name__ == "__main__":
    raise RuntimeError("This is a library, not meant to run on its own.")
