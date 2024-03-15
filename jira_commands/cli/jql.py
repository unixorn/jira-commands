# JQL query support
#
# Author: Joe Block <jblock@zscaler.com>
# License: Apache 2.0
# Copyright 2024, ZScaler Inc.

import logging

from jira_commands import __version__ as cli_version
from jira_commands.cli.common import (
    base_cli_parser,
)
from jira_commands.jira import JiraTool, load_jira_settings


def parse_jql_cli(description: str = f"Run a JQL query {cli_version}"):
    """
    Run a JQL query
    """
    parser = base_cli_parser(description=description)

    parser.add_argument(
        "--jql", "--jql-query", type=str, required=True, help="JQL query to run"
    )
    cli = parser.parse_args()
    loglevel = getattr(logging, cli.log_level.upper(), None)
    logFormat = "[%(asctime)s][%(levelname)8s][%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
    logging.basicConfig(level=loglevel, format=logFormat)
    logging.info("Set log level to %s", cli.log_level.upper())
    return cli


def run_jql():
    """
    Run a JQL query
    """
    cli = parse_jql_cli(description="Run a JQL query")
    logging.debug(f"cli: {cli}")

    settings = load_jira_settings(path=cli.settings_file, cli=cli)

    jira = JiraTool(settings=settings)
    print(jira.jql(jql=cli.jql))
