#
# Vivisect a jira ticket so we can figure out the data structure and custom
# fields for a specific ticket type.
#
# Author: Joe Block <jblock@zscaler.com>
# License: Apache 2.0
# Copyright 2022-2023, ZScaler Inc.

import json
import logging
import pprint

from jira_commands.cli.common import base_cli_parser, parse_ticket_cli
from jira_commands.jira import JiraTool, load_jira_settings


def dump_all_customfield_allowed_values():
    """
    Dump all the customfield allowed options for a given ticket
    """
    cli = parse_dump_all_customfields_cli()
    logging.debug(f"cli: {cli}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    allowed_dict = jira.load_customfield_allowed_values(ticket=cli.ticket)
    print(json.dumps(allowed_dict))


def parse_dump_all_customfields_cli():
    """
    Parse the command line options for jc-ticket-dump-all-customfields
    """
    parser = parse_ticket_cli(description="Dump a ticket's metadata")

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

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    metadata = jira.get_issue_metadata(ticket=cli.ticket)
    print(f"  {pprint.pformat(metadata, indent=2)}")


def extract_allowed_values():
    cli = parse_ticket_field_cli(
        description="Get the allowed values for custom field on a ticket. "
        " Jira's API requires it be read from a ticket, not an issue type."
    ).parse_args()

    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cli.log_level.upper())

    logging.debug(f"cli: {cli}")
    logging.debug(f"ticket: {cli.ticket}")
    logging.debug(f"custom_field: {cli.custom_field}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)
    jira = JiraTool(settings=settings)
    human_names = jira.customfield_id_map(ticket=cli.ticket)
    custom_field_name = human_names[cli.custom_field]

    print(f"Values for {cli.custom_field} of {cli.ticket} aka '{custom_field_name}':")
    field_allowed_values = jira.allowed_values_for_field(
        ticket=cli.ticket, custom_field=cli.custom_field
    )
    print(f"  {pprint.pformat(field_allowed_values,indent=2)}")


def parse_metadata_cli():
    """
    Parse the command line options for jc-ticket-metadata
    """
    parser = parse_ticket_cli(description="Dump a ticket's metadata")

    cliArgs = parser.parse_args()
    loglevel = getattr(logging, cliArgs.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cliArgs.log_level.upper())
    return cliArgs


def parseVivisectCLI():
    logging.warning(
        "parseVivisectCLI is deprecated and will be removed soon. Use parse_vivisect_cli instead"
    )
    return parse_vivisect_cli()


def parse_vivisect_cli():
    """
    Parse the command line options
    """
    parser = parse_ticket_cli(
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
    cli = parse_vivisect_cli()
    logging.debug(f"cli: {cli}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    jira.vivisect(ticket_id=cli.ticket)


def parseTicketFieldCLI(description: str):
    logging.warning(
        "parseTicketFieldCLI is deprecated and will be removed, use parse_ticket_field_cli instead"
    )
    return parse_ticket_field_cli(description=description)


def parse_ticket_field_cli(description: str):
    """
    Parse the command line options and return the ticket id
    """
    parser = base_cli_parser(description=description)

    parser.add_argument("--ticket", "-t", type=str, required=True)
    parser.add_argument("--custom-field", "-c", type=str, required=True)
    return parser


def listAllowedFieldValues():
    logging.warning(
        "listAllowedFieldValues is deprecated and will be removed, use parse_ticket_field_cli instead"
    )


def list_allowed_field_values():
    """
    Get the allowed values for a ticket's custom fields.

    JIRA won't let us do this by issue type because that would be too logical,
    we have to examine a ticket instead.
    """
    cli = parse_ticket_field_cli(
        description="Get the allowed values for a ticket's custom fields"
    ).parse_args()

    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cli.log_level.upper())

    logging.debug(f"cli: {cli}")
    logging.debug(f"ticket: {cli.ticket}")
    logging.debug(f"custom_field: {cli.custom_field}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)
    jira = JiraTool(settings=settings)
    print(f"Values for {cli.ticket}'s {cli.custom_field}:")
    for allowed in jira.allowed_values_for_field(
        ticket=cli.ticket, custom_field=cli.custom_field
    ):
        print(f"  {pprint.pformat(allowed, indent=2)}")


if __name__ == "__main__":
    raise RuntimeError("This is a library, not meant to run on its own.")
