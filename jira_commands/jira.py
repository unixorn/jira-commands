#!/usr/bin/env python3
#
# Author: Joe Block <jblock@zscaler.com>
# License: Apache 2.0
# Copyright 2022, ZScaler Inc.
#
# Interact with JIRA

import getpass
import json
import logging
import requests
from requests.auth import HTTPBasicAuth

from jira import JIRA
from jira_commands.utils import dumpObject
from thelogrus.yaml import readYamlFile


def loadJiraSettings(path: str, cli):
    """
    Load JIRA settings from a yaml file, allowing overrides from the CLI
    """
    settings = readYamlFile(path=path)
    # Command line arguments should override the settings file
    if cli.server:
        settings["jira_server"] = cli.server

    if cli.username:
        settings["username"] = cli.username

    if cli.password:
        settings["password"] = cli.password

    if "username" not in settings:
        settings["username"] = input("Username: ")

    if "password" not in settings:
        settings["password"] = getpass.getpass("Password: ")

    # Make sure we have all the settings we need
    if "jira_server" not in settings:
        raise RuntimeError("You must specify the jira server")
    if not settings["username"]:
        raise RuntimeError("You must specify the jira server username")
    if not settings["password"]:
        raise RuntimeError("You must specify the jira server password")

    logging.debug(f"Using JIRA server: {settings['jira_server']}")
    logging.debug(f"username: {settings['username']}")

    credentials = {"username": settings["username"], "password": settings["password"]}
    if "credentials" not in settings:
        logging.debug("Setting credentials key in settings")
        settings["credentials"] = credentials
    else:
        logging.warning(f"There is already a credentials key in {path}")
    return settings


def makeIssueData(cli):
    """
    Create issue_data from command line arguments

    This sets up the standard issue data fields - if a JIRA project has
    custom fields, it should get it's own issueData function that starts
    by calling this.

    returns dict
    """
    try:
        if cli.json:
            issue_data = json.loads(cli.json)
            logging.debug(f"issue_data (from --json): {issue_data}")
        else:
            logging.debug("Starting with blank issue data")
            issue_data = {}
    except AttributeError:
        logging.warning("No json command line argument found")

    if cli.description:
        logging.debug(f"description: {cli.description}")
        issue_data["description"] = cli.description

    if cli.issue_type:
        logging.debug(f"issue_type: {cli.issue_type}")
        issue_data["issuetype"] = cli.issue_type

    if cli.label:
        logging.debug(f"label: {cli.label}")
        issue_data["label"] = cli.label

    if cli.project:
        logging.debug(f"project: {cli.project}")
        issue_data["project"] = cli.project

    if cli.summary:
        logging.debug(f"summary: {cli.summary}")
        issue_data["summary"] = cli.summary

    return issue_data


def linkIssuesHack(
    source: str,
    target: str,
    link_type: str,
    username: str,
    password: str,
    jira_server: str,
):
    """
    Link two issues

    This is a horrible hack because the jira module fails with a permission
    error when I use its create_issue_link method, but I can use the same
    username and password with curl against the JIRA API directly and that
    works, so created an issue upstream and I'm using this requests.get hack
    until https://github.com/pycontribs/jira/issues/1296 is fixed upstream.

    Based on https://confluence.atlassian.com/jirakb/how-to-use-rest-api-to-add-issue-links-in-jira-issues-939932271.html
    """

    # This is documented to work, but returns an error that we don't have
    # link issue permission.

    # logging.info(f"Creating '{link_type}' link from {source} to {target}")
    # result = self.connection.create_issue_link(
    #     type=link_type, inwardIssue=source, outwardIssue=target
    # )

    data = {
        "update": {
            "issuelinks": [
                {
                    "add": {
                        "type": {
                            "name": link_type,
                        },
                        "outwardIssue": {"key": target},
                    }
                }
            ]
        }
    }
    url = f"{jira_server}/rest/api/2/issue/{source}"

    logging.debug(f"username: {username}")
    logging.debug(f"url: {url}")
    logging.debug(f"data: {data}")

    results = requests.put(url, auth=HTTPBasicAuth(username, password), json=data)
    logging.debug(f"status code: {results.status_code}")
    if results.status_code >= 200 and results.status_code < 300:
        logging.debug("Successful")
        logging.debug(f"results: {results}")
        status = True
    else:
        logging.error(f"Call failed: {results.status_code}")
        logging.error(f"results: {results}")
        status = False
    return status


class JiraTool:
    # Jira housekeeping
    def __init__(self, settings: dict):
        """
        Create a JIRA helper object
        """
        self.username = settings["username"]
        self.password = settings["password"]
        self.jira_server = settings["jira_server"]
        self.connect()

    def __str__(self):
        """
        Print a representation of the object
        """
        raw = {"username": self.username, "jira_server": self.jira_server}
        return raw.__str__()

    def connect(self):
        jiraOptions = {"server": self.jira_server}
        jiraBasicAuth = (self.username, self.password)
        logging.debug(
            f"Creating connection to {self.jira_server} with user {self.username}"
        )
        self.connection = JIRA(options=jiraOptions, basic_auth=jiraBasicAuth)

    # Utility functions
    def assignTicket(self, ticket: str, assignee: str):
        """
        Assign a ticket
        """
        logging.debug(f"Assigning {ticket} to {assignee}")
        return self.connection.assign_issue(ticket, assignee)

    def unassignTicket(self, ticket: str):
        """
        Assign a ticket to no one
        """
        logging.debug(f"Assigning {ticket} to No one")
        return self.connection.assign_issue(ticket, None)

    def addComment(self, ticket: str, comment: str):
        """
        Comment on a ticket
        """
        if comment:
            logging.debug(f"Adding comment {comment} to ticket {ticket}")
            return self.connection.add_comment(ticket, comment)
        else:
            raise RuntimeError("You must specify a comment to add to the ticket")

    def createTicket(self, issue_data: dict, priority: str = None, strict=True):
        """
        Create a JIRA ticket from a data dictionary
        """
        logging.debug(f"Creating ticket using {issue_data}")
        # Make sure we have a minimum set of fields
        required = [
            "description",
            "summary",
            "project",
            "issuetype",
        ]
        if strict:
            valid = True
            for r in required:
                if r not in issue_data:
                    valid = False
                    logging.error(f"{r} not specified in issue_data")
            if not valid:
                logging.critical(
                    f"You must specify all the mandatory issue fields: {required}"
                )
                raise ValueError(
                    f"You must specify all the mandatory issue fields: {required}"
                )

        if priority:
            logging.debug(f"Setting ticket priority to {priority}")
            priority_info = self.getPriorityDict()
            priority_data = {"id": priority_info[priority]}
            issue_data["priority"] = priority_data

        new_issue = self.connection.create_issue(fields=issue_data)
        return new_issue

    def createSubtask(self, issue_data: dict, parent: str):
        """
        Create a subtask
        """
        logging.warning("Creating a subtask")
        if not parent:
            logging.error("You must specify a parent ticket when creating a Sub-Task")
            raise ValueError(
                "You must specify a parent ticket when creating a Sub-Task"
            )
        issue_data["parent"] = {"id": parent}
        return self.createTicket(issue_data=issue_data)

    def linkIssues(self, source, target, link_type):
        """
        Link two issues
        """
        # Jira is inconsistent about when you can use string ticket ids and
        # when you have to use issue objects
        source_issue = self.connection.issue(source)
        target_issue = self.connection.issue(target)
        logging.debug(f"source_issue: {source_issue}")
        logging.debug(f"target_issue: {target_issue}")

        # Link the two issues
        return linkIssuesHack(
            username=self.username,
            password=self.password,
            link_type=link_type,
            source=source,
            target=target,
            jira_server=self.jira_server,
        )

    def listTickets(self, project: str):
        for singleIssue in self.connection.search_issues(
            jql_str=f"project = {project}"
        ):
            print(
                f"{singleIssue.key} {singleIssue.fields.summary} {singleIssue.fields.reporter.displayName}"
            )

    def getPriorityDict(self):
        """
        Returns a dictionary of all the priorities on a server and their IDs
        """
        raw_priorities = self.connection.priorities()
        priority_data = {}

        for priority in raw_priorities:
            logging.debug(f"{priority.name} : {priority.id}")
            priority_data[priority.name] = priority.id
        return priority_data

    def getTicket(self, ticket: str):
        """
        Peel a ticket out of JIRA
        """
        issue = self.connection.issue(ticket)
        return issue

    def vivisect(self, ticket_id: str):
        """
        Vivisect a ticket so we can figure out what attributes are visible
        via the module's API.
        """
        ticket = self.getTicket(ticket=ticket_id)
        print(f"ticket: {ticket}")
        print("ticket transitions available:")
        for transition in self.connection.transitions(ticket):
            print(f"  {transition}")
        print(f"ticket.fields.issuetype: {ticket.fields.issuetype}")
        print(f"ticket.fields.issuelinks: {ticket.fields.issuelinks}")
        print(f"ticket.fields.issuelinks repr: {ticket.fields.issuelinks.repr()}")
        print(f"ticket.fields.issuelinks dump: {dumpObject(ticket.fields.issuelinks)}")
        print(f"ticket.fields: {ticket.fields}")
        print()
        print(f"ticket.fields (dump): {dumpObject(ticket.fields)}")

    def getTicketDict(self, project: str):
        """
        Get JIRA tickets in a project, return as a dict
        """
        tickets = {}
        for singleIssue in self.connection.search_issues(
            jql_str=f"project = {project}"
        ):
            tickets[singleIssue.key] = singleIssue
            logging.debug(f"{singleIssue.key} : {singleIssue}")
            logging.debug(f"{singleIssue.key} : fields {singleIssue.fields}")
            logging.debug(f"dumpObj(singleIssue : {dumpObject(singleIssue)}")
            logging.debug(" ")
        return tickets

    def transitionTicket(self, ticket: str, state: str, comment: str = None):
        """
        Transition a ticket to a new state
        """
        issue = self.connection.issue(ticket)
        available_transitions = self.ticketTransitions(ticket=ticket)

        if state in available_transitions:
            logging.info(f"Transitioning issue {ticket} to state {state}")
            if comment:
                self.addComment(ticket=ticket, comment=comment)
            return self.connection.transition_issue(issue, available_transitions[state])
        else:
            raise ValueError(
                f"{ticket} does not have {state} as an available transition. Perhaps your user doesn't have privilege for that?"
            )

    # Internal helpers
    def ticketTransitions(self, ticket: str):
        """
        Find the available transitions for a given ticket
        """

        # Map the names to ids so the caller can user a human-understandable
        # name instead of having to track down the id.
        transitions = {}
        for t in self.connection.transitions(ticket):
            logging.debug(f"Found transition '{t['name']}, id {t['id']}")
            transitions[t["name"]] = t["id"]
        logging.debug(f"Transition lookup table: {transitions}")
        return transitions
