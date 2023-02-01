#!/usr/bin/env python3
#
# Extract the mappings from an issue to use in ticket creation
#
# We have to do this ugly hackery because JIRA will sometimes renumber
# the mappings in a given issue type if you change any of the dropdown
# menu options.
#
# For extra fun, it will even renumber options in the dropdowns you
# _didn't_ edit sometimes.

import logging
import re

from thelogrus.yaml import writeYamlFile

from jira_commands.cli.common import baseCLIParser
from jira_commands.jira import JiraTool, loadJiraSettings


def mappings_extractor_parser(
    description: str = "Extract field maps for a JIRA issue type from a golden issue",
):
    parser = baseCLIParser(description=description)
    parser.add_argument(
        "--mapping-output-file",
        help="Where to write the extracted JIRA field mappings",
        type=str,
        required=True,
    )
    parser.add_argument(
        "--template-ticket",
        "--get-field-choices-from",
        type=str,
        help="Read valid dropdowns from a ticket. JIRA occasionally renumbers the dropdowns if _any_ dropdown for an issue type is modified.",
    )
    return parser


def mappings_extractor_cli(
    description: str = "Extract field maps for a JIRA issue type from a golden issue",
):
    """
    Parse command line options for the custom mapping file creator
    """
    parser = mappings_extractor_parser(description=description)

    cli = parser.parse_args()
    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cli.log_level.upper())
    return cli


def cleanup_mappings(data: dict = None):
    """
    We only need the customfield_* keys, not the extra garbage jira returned
    Args:
        data: dictionary to purge irrelevant entries from
    Returns:
        dict with the irrelevant entries removed
    """
    logging.info("Cleaning up field mappings data")
    badkeys = []
    for k in data.keys():
        valid = r"customfield_.*"
        check = re.search(valid, k)
        if not check:
            badkeys.append(k)
    for b in badkeys:
        logging.warning(f"Removing invalid key {b}")
        data.pop(b)
    return data


def create_mapping_file():
    """
    Create an mapping file for the custom fields in an issue type
    """
    cli = mappings_extractor_cli()

    settings = loadJiraSettings(path=cli.settings_file, cli=cli)
    logging.debug(f"settings: {settings}")

    jira = JiraTool(settings=settings)
    allowed_dict = cleanup_mappings(
        jira.load_customfield_allowed_values(ticket=cli.template_ticket)
    )
    logging.info(f"Writing to {cli.mapping_output_file}")
    writeYamlFile(path=cli.mapping_output_file, data=allowed_dict)
