#
# Author: Joe Block <jblock@zscaler.com>
# License: Apache 2.0
# Copyright 2022-2023, ZScaler Inc.
#
# Interact with JIRA

from functools import lru_cache
import getpass
import json
import logging
import requests

from jira import JIRA
from jira_commands.utils import dump_object
from thelogrus.yaml import readYamlFile


def loadJiraSettings(path: str, cli):
    logging.warning(
        "loadJiraSettings() is deprecated and will be removed soon, use load_jira_settings()"
    )
    return load_jira_settings(path=path, cli=cli)


def load_jira_settings(path: str, cli):
    """
    Load JIRA settings from a yaml file, allowing overrides from the CLI

    Args:
        path: Path to configuration file
        cli (argparse cli object): Command line options

    Returns:
        dict: A dictionary containing all of our settings
    """
    settings = readYamlFile(path=path)

    # Command line arguments should override the settings file
    if cli.server:
        settings["jira_server"] = cli.server

    if cli.username:
        settings["username"] = cli.username

    if cli.password:
        settings["password"] = cli.password

    settings["auth"] = cli.auth

    # Make sure we have all the settings we need
    if "jira_server" not in settings:
        raise RuntimeError("You must specify the jira server")

    if cli.auth == "BASIC":
        # We can fall back to asking the user if we're doing basic auth
        if "username" not in settings:
            settings["username"] = input("Username: ")

        if "password" not in settings:
            settings["password"] = getpass.getpass("Password: ")

        logging.debug("Using basic auth")
        if not settings["username"]:
            raise RuntimeError("You must specify the jira server username")
        if not settings["password"]:
            raise RuntimeError("You must specify the jira server password")

        credentials = {
            "username": settings["username"],
            "password": settings["password"],
        }
        if "credentials" not in settings:
            logging.debug("Setting credentials key in settings")
            settings["credentials"] = credentials
        else:
            logging.warning(f"There is already a credentials key in {path}")

    if cli.auth == "OAUTH":
        logging.debug("Auth set to OAUTH")
        settings["oauth_access_token"] = cli.oauth_access_token
        settings["oauth_access_token_secret"] = cli.oauth_access_token_secret
        settings["oauth_consumer_key"] = cli.oauth_consumer_key
        settings["oauth_private_key_pem_path"] = cli.oauth_private_key_pem_path
        # We need all of these when auth is set to OAUTH
        logging.info(f"settings: {settings}")
        if "oauth_access_token" not in settings:
            raise RuntimeError(
                "You must specify an Oauth access_token when auth is set to OAUTH"
            )
        if "oauth_access_token_secret" not in settings:
            raise RuntimeError(
                "You must specify an Oauth access_token_secret when auth is set to OAUTH"
            )
        if "oauth_consumer_key" not in settings:
            raise RuntimeError(
                "You must specify an Oauth consumer_key when auth is set to OAUTH"
            )
        if "oauth_private_key_pem_path" not in settings:
            raise RuntimeError(
                "You must specify the path to a pem file containing the Oauth private key when auth is set to OAUTH"
            )

    if cli.auth == "PAT":
        logging.debug("Auth set to PAT")
        if hasattr(cli, "pat_token"):
            if cli.pat_token:
                settings["pat_token"] = cli.pat_token
            else:
                logging.debug("cli pat token is None")
                if "pat_token" in settings:
                    logging.debug("Found pat token in settings...")
        if "pat_token" not in settings:
            settings["pat_token"] = input("pat_token: ")

    logging.debug(f"Using JIRA server: {settings['jira_server']}")
    logging.debug(f"username: {settings['username']}")

    return settings


def makeIssueData(cli):
    logging.warning(
        "makeIssueData() is deprecated and will be removed soon, use make_issue_data()"
    )
    return make_issue_data(cli=cli)


def make_issue_data(cli):
    """
    Create issue_data from command line arguments

    This sets up the standard issue data fields - if a JIRA project has
    custom fields, it should get it's own issueData function that starts
    by calling this.

    Args:
        cli (argparse cli): Command line arguments

    Returns:
        dict: A dictionary containing data fields to be used to create a JIRA issue.
    """
    try:
        if hasattr(cli, "json"):
            if cli.json:
                issue_data = json.loads(cli.json)
                logging.debug(f"issue_data (from --json): {issue_data}")
            else:
                logging.debug("json cli argument is None, leaving it unset")
                issue_data = {}
        else:
            logging.debug("Starting with blank issue data")
            issue_data = {}
    except AttributeError as missing_json:
        logging.warning("No json command line argument found")
        raise missing_json

    if hasattr(cli, "description"):
        if cli.description:
            logging.debug(f"description: {cli.description}")
            issue_data["description"] = cli.description
        else:
            issue_data["description"] = "No description set"

    if hasattr(cli, "issue_type"):
        logging.debug(f"issue_type: {cli.issue_type}")
        issue_data["issuetype"] = cli.issue_type

    if hasattr(cli, "label"):
        if cli.label:
            logging.debug(f"label: {cli.label}")
            issue_data["label"] = cli.label

    if hasattr(cli, "project"):
        logging.debug(f"project: {cli.project}")
        issue_data["project"] = cli.project

    if hasattr(cli, "summary"):
        if cli.summary:
            logging.debug(f"summary: {cli.summary}")
            issue_data["summary"] = cli.summary
        else:
            issue_data["summary"] = "No ticket summary set"

    return issue_data


class JiraTool:
    # Jira housekeeping
    def __init__(self, settings: dict):
        """
        Create a JIRA helper object.

        This wraps an upstream JIRA object with helper methods and breakfixes
        to make it less painful to use.

        It's still painful, just less so that using the upstream module.

        Args:
            settings: All settings required to connect to JIRA.
        """

        self.jira_server = settings["jira_server"]
        self.auth = settings["auth"]
        self.supported_authentications = ["basic", "oauth", "pat"]

        # Basic AUTH
        if "username" in settings:
            self.username = settings["username"]
        if "password" in settings:
            self.password = settings["password"]

        # Load OAUTH credentials
        if "oauth_access_token" in settings:
            self.oauth_access_token = settings["oauth_access_token"]
        if "oauth_access_token_secret" in settings:
            self.oauth_access_token_secret = settings["oauth_access_token_secret"]
        if "oauth_consumer_key" in settings:
            self.oauth_consumer_key = settings["oauth_consumer_key"]
        if "oauth_private_key_pem_path" in settings:
            self.oauth_private_key_pem_path = settings["oauth_private_key_pem_path"]

        # PAT token
        if "pat_token" in settings:
            self.pat_token = settings["pat_token"]

        self.connect(auth=settings["auth"])

    def __str__(self):
        """
        Print a representation of the object
        """
        raw = {"username": self.username, "jira_server": self.jira_server}
        return raw.__str__()

    def connect(self, auth: str = "basic"):
        """
        Connects to JIRA and stores the connection object as a property.
        Reads required data from the JiraTool object's properties.

        Args:
            auth: What type of authentication to use to connect to JIRA. Allowed options are ["basic", "oauth", "pat"]
        """
        jiraOptions = {"server": self.jira_server}
        logging.debug(f"Connecting to {self.jira_server} using {auth} authentication.")

        if auth.lower() not in self.supported_authentications:
            raise NotImplementedError(
                f"'{auth}' is not a valid authentication type. The only valid types are {', '.join(self.supported_authentications)}"
            )

        if auth.lower() == "basic":
            jiraBasicAuth = (self.username, self.password)
            logging.debug(
                f"Creating connection to {self.jira_server} with user {self.username}"
            )
            self.connection = JIRA(options=jiraOptions, basic_auth=jiraBasicAuth)  # type: ignore

        if auth.lower() == "oauth":
            with open(self.oauth_private_key_pem_path, "r") as key_cert_file:
                key_cert_data = key_cert_file.read()

            oauth_dict = {
                "access_token": self.oauth_access_token,
                "access_token_secret": self.oauth_access_token_secret,
                "consumer_key": self.oauth_consumer_key,
                "key_cert": key_cert_data,
            }
            logging.debug(
                f"Creating connection to {self.jira_server} with Oauth athentication, consumer key {self.oauth_consumer_key}"
            )
            self.connection = JIRA(options=jiraOptions, oauth=oauth_dict)

        if auth.lower() == "pat":
            logging.debug(
                f"Creating connection to {self.jira_server} with PAT authentication"
            )
            self.connection = JIRA(options=jiraOptions, token_auth=self.pat_token)

    # Field manipulations

    @lru_cache(maxsize=128)
    def allowed_values_for_field(self, ticket: str, custom_field: str):
        """
        Get the allowed values for a custom field on an issue

        JIRA isn't very forgiving about ticket values, so provide a way to
        extract what it's expecting to find in a given custom field.

        Args:
            ticket: The ticket to load values from.
            custom_field: Which custom field to determine valid values for.

        Returns:
            dict: A dictionary containing all the allowed values for field custom_field.
        """
        logging.debug(f"connection: {self.connection}")

        issue = self.get_issue_data(ticket)
        logging.debug(f"issue: {issue}")

        meta = self.get_issue_metadata(ticket=ticket)
        raw_fields = meta["fields"][custom_field]["allowedValues"]
        allowed = {}
        for r in raw_fields:
            allowed[r["value"]] = r["id"]
        return allowed

    @lru_cache(maxsize=128)
    def customfield_id_map(self, ticket: str):
        """
        Create a dict keyed by customfield id with the the human names for
        a ticket's custom fields.

        JIRA's API won't let you get the custom field data from an issue
        type because that would be too logical. Instead, you have to read
        them from an existing ticket of the type, which encourages people
        to keep golden tickets lying around.

        Instead of winning a trip to Wonka's factory, all you get for a
        golden ticket is more aggravation from JIRA when someone inevitably
        deletes them.

        Args:
            ticket: which ticket to load custom field data from

        Returns:
            dict containing customfield id -> human name mappings
        """
        issue = self.get_issue_data(ticket)
        logging.debug(f"issue: {issue}")
        meta = self.get_issue_metadata(ticket=ticket)
        fields = meta["fields"]
        logging.debug(f"fields: {fields.keys()}")

        allfields = self.connection.fields()
        name_map = {
            self.connection.field["id"]: self.connection.field["name"]
            for self.connection.field in allfields
        }
        logging.debug(f"name_map: {name_map}")
        return name_map

    @lru_cache(maxsize=128)
    def customfield_title(self, ticket: str, custom_field: str) -> str:
        """
        Return the human name of a custom field

        Args:
            ticket: ticket to read field data from
            custom_field: which field

        Returns:
            str human readable name of the custom field
        """
        human_names = self.customfield_id_map(ticket=ticket)
        return human_names[custom_field]

    def get_issue_subtasks(self, ticket: str):
        """
        Return the list of subtask objects in the specified jira issue
        """
        issue = self.get_issue_data(ticket)
        return issue.fields.subtasks

    def list_issue_subtasks(self, ticket: str):
        """
        Return a list of all subtasks for the specified jira issue
        """
        subtasks = self.get_issue_subtasks(ticket)
        logging.debug(f"subtasks: {subtasks}")
        subtask_list = []
        logging.debug(f"subtasks: {subtasks}")
        for k in subtasks:
            logging.debug(f"subtask: {k.key}")
            subtask_list.append(k.key)
        subtask_list.sort()
        return subtask_list

    def updateField(self, ticket: str, custom_field: str, value, field_type: str):
        logging.warning(
            "JiraTool.updateField() is deprecated and will be removed soon, use JiraTool.update_field"
        )
        return self.update_field(
            ticket=ticket, custom_field=custom_field, value=value, field_type=field_type
        )

    def update_field(self, ticket: str, custom_field: str, value, field_type: str):
        """
        Update a field on an issue.

        Args:
            ticket: Which ticket to update.
            custom_field: Which field to alter
            field_type: JIRA's API is too janky to figure this out
                for itself, even though it knows what the field type is,
                so we have to specify it.
            value (varies): Varies based on field_type.

        Returns:
            Update results

        Raises:
            Re-raises any exceptions from underlying JIRA object during update
        """
        try:
            issue = self.get_ticket(ticket=ticket)
            logging.debug("Updating issue: %s", issue)
            fields = {}
            fields = self.update_field_dict(
                custom_field=custom_field,
                value=value,
                field_type=field_type,
                fields=fields,
            )
            return issue.update(fields=fields)
        except Exception as jiraConniption:
            logging.exception(jiraConniption)
            raise jiraConniption

    def updateMultipleFields(self, ticket: str, fields: dict):
        logging.warning(
            "JiraTool.updateField() is deprecated and will be removed soon, use JiraTool.update_field"
        )
        return self.update_multiple_fields(ticket=ticket, fields=fields)

    def update_multiple_fields(self, ticket: str, fields: dict):
        """
        Update multiple fields from a fields dictionary

        Args:
            ticket: Which ticket to update
            fields: A dictionary with keys for each field we need to update

        Raises:
            Re-raises any exceptions from underlying JIRA object during update
        """
        try:
            issue = self.get_ticket(ticket=ticket)
            logging.debug("Updating %s using %s", issue, fields)
            return issue.update(fields=fields)
        except Exception as jiraConniption:
            logging.exception(jiraConniption)
            raise jiraConniption

    # Utility functions
    def assignTicket(self, ticket: str, assignee: str):
        logging.warning(
            "JiraTool.assignTicket() is deprecated and will be removed soon, use JiraTool.assign_ticket"
        )
        return self.assign_ticket(ticket=ticket, assignee=assignee)

    def assign_ticket(self, ticket: str, assignee: str):
        """
        Assign a ticket

        Args:
            ticket: What ticket to assign
            assignee: Who to assign it to

        Returns:
            Update results
        """
        logging.debug(f"Assigning {ticket} to {assignee}")
        return self.connection.assign_issue(ticket, assignee)

    def unassignTicket(self, ticket: str):
        logging.warning(
            "JiraTool.unassignTicket is deprecated and will be removed soon, use JiraTool.unassign_ticket"
        )
        return self.unassign_ticket(ticket=ticket)

    def unassign_ticket(self, ticket: str):
        """
        Assign a ticket to no one

        Args:
            ticket: Which ticket to remove the assignee from

        Returns:
            Ticket update results
        """
        logging.debug(f"Assigning {ticket} to No one")
        return self.connection.assign_issue(ticket, None)

    def addComment(self, ticket: str, comment: str):
        logging.warning(
            "JiraTool.unassignTicket is deprecated and will be removed soon, use JiraTool.unassign_ticket"
        )
        return self.add_comment(ticket=ticket, comment=comment)

    def add_comment(self, ticket: str, comment: str):
        """
        Comment on a ticket.

        Args:
            ticket: Ticket to comment on
            comment: Comment to add

        Returns:
            Ticket update results
        """
        if comment:
            logging.debug(f"Adding comment {comment} to ticket {ticket}")
            return self.connection.add_comment(ticket, comment)
        else:
            raise RuntimeError("You must specify a comment to add to the ticket")

    def createTicket(
        self,
        issue_data: dict,
        priority: str = None,
        strict: bool = True,
        required_fields: list = None,
    ):
        logging.warning(
            "JiraTool.createTicket() is deprecated and will be removed soon, use JiraTool.create_ticket"
        )
        return self.create_ticket(
            issue_data=issue_data,
            priority=priority,
            strict=strict,
            required_fields=required_fields,
        )

    def create_ticket(
        self,
        issue_data: dict,
        priority: str = None,
        strict: bool = True,
        required_fields: list = None,
    ):
        """
        Creates a JIRA ticket from a data dictionary.

        Args:
            issue_data: dictionary with keys for every field we want
            to set during ticket creation.
            priority: What priority to assign the new ticket
            required_fields: What fields to ensure are set during creation
            strict: Enforce the required_fields

        Returns:
            Newly created issue
        """
        logging.debug(f"Creating ticket using {issue_data}")
        # Make sure we have a minimum set of fields
        logging.debug(f"required_fields: {required_fields}")
        if not required_fields:
            required_fields = []
        if strict:
            valid = True
            for r in required_fields:
                if r not in issue_data:
                    valid = False
                    logging.error(f"{r} not specified in issue_data")
            if not valid:
                logging.critical(
                    f"You must specify all the mandatory issue fields: {required_fields}"
                )
                raise ValueError(
                    f"You must specify all the mandatory issue fields: {required_fields}"
                )
        if priority:
            logging.debug(f"Setting ticket priority to {priority}")
            priority_info = self.get_priority_dict()
            priority_data = {"id": priority_info[priority]}
            issue_data["priority"] = priority_data
        logging.debug(f"issue_data: {issue_data}")
        new_issue = self.connection.create_issue(fields=issue_data)
        logging.debug(f"new_issue: {new_issue}")
        return new_issue

    def createSubtask(
        self,
        issue_data: dict,
        parent: str,
        required_fields: list = None,
        strict: bool = True,
    ):
        logging.warning(
            "JiraTool.createSubtask() is deprecated and will be removed soon, use JiraTool.create_subtask"
        )
        return self.create_subtask(
            issue_data=issue_data,
            parent=parent,
            required_fields=required_fields,
            strict=strict,
        )

    def create_subtask(
        self,
        issue_data: dict,
        parent: str,
        required_fields: list = None,
        strict: bool = True,
    ):
        """
        Create a subtask.

        Creates a subtask on an existing ticket.

        Args:
            issue_data: Field data for the new subtask.
            parent: Ticket to add a subtask to.
            required_fields: List of fields to enforce in the subtask if strict is set.
            strict: Whether or not to enforce the field list. Defaults to True.

        Returns:
            Ticket ID of new subtask
        """
        logging.debug("Creating a subtask")
        if not parent:
            logging.error("You must specify a parent ticket when creating a Sub-Task")
            raise ValueError(
                "You must specify a parent ticket when creating a Sub-Task"
            )
        issue_data["parent"] = {"id": parent}
        logging.debug(f"required_fields: {required_fields}")
        return self.create_ticket(
            issue_data=issue_data, required_fields=required_fields, strict=strict
        )

    def getIssueData(self, ticket: str):
        logging.warning(
            "JiraTool.getIssueData() is deprecated and will be removed soon, use JiraTool.get_issue_data()"
        )
        return self.get_issue_data(ticket=ticket)

    def get_issue_data(self, ticket: str):
        """
        Returns the JIRA issue data for a ticket

        This is a shim to keep JiraTool users from having to rummage through
        its internals to use the jira object it's connecting to your jira
        server with.

        Args:
            ticket: JIRA ticket number
        """
        return self.connection.issue(ticket)

    def get_issue_type(self, ticket: str) -> str:
        """
        Convenience function to get the issue type for an issue

        Args:
            ticket: JIRA ticket number

        Returns:
            str issue type
        """
        issue = self.get_issue_data(ticket)
        return issue.fields.issuetype.name

    def getIssueMetaData(self, ticket: str):
        logging.warning(
            "JiraTool.getIssueMetaData() is deprecated and will be removed soon, use JiraTool.get_issue_metadata()"
        )
        return self.get_issue_metadata(ticket=ticket)

    def get_issue_metadata(self, ticket: str):
        """
        Get an issue's metadata.

        This is a shim to keep JiraTool users from having to rummage through
        its internals to use the jira object it's connecting to your jira
        server with.

        Args:
            ticket: JIRA ticket number
        """
        issue = self.get_issue_data(ticket=ticket)
        meta = self.connection.editmeta(issue)
        return meta

    def linkIssues(self, source: str, target: str, link_type: str):
        logging.warning(
            "JiraTool.linkIssues() is deprecated and will be removed soon, use JiraTool.link_issues()"
        )
        return self.link_issues(source=source, target=target, link_type=link_type)

    def link_issues(self, source: str, target: str, link_type: str):
        """
        Link two issues

        This is a horrible hack because the jira module fails with a permission
        error when I use its create_issue_link method, but I can use the same
        username and password with curl against the JIRA API directly and that
        works, so I created an issue upstream.

        I'm using this requests.put hack until https://github.com/pycontribs/jira/issues/1296
        is fixed upstream.

        Based on https://confluence.atlassian.com/jirakb/how-to-use-rest-api-to-add-issue-links-in-jira-issues-939932271.html

        Args:
            source: ticket id of source ticket
            target: ticket id of target ticket
            link_type: What kind of linkage (Blocks, Related, etc)

        Returns:
            bool : Whether or not the link was successfully created
        """
        # Jira is inconsistent about when you can use string ticket ids and
        # when you have to use issue objects
        source_issue = self.connection.issue(source)
        target_issue = self.connection.issue(target)
        logging.debug(f"source_issue: {source_issue}")
        logging.debug(f"target_issue: {target_issue}")

        # This is documented to work, but returns an error that we don't have
        # link issue permission.

        # logging.info(f"Creating '{link_type}' link from {source} to {target}")
        # result = self.connection.create_issue_link(
        #     type=link_type, inwardIssue=source, outwardIssue=target
        # )

        # Instead, we're going to hit the REST api ourselves :-(

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
        url = f"{self.jira_server}/rest/api/2/issue/{source}"

        logging.debug(f"url: {url}")
        logging.debug(f"data: {data}")

        # Instead of maessing with creating our own oauth or PAT credential,
        # extract the auth method & data out of the JIRA object created in our
        # connect() method.
        # Ugly, but better than trying to do it ourselves.
        jira_auth = self.connection._session.auth

        logging.debug(f"Auth: {jira_auth}")
        results = requests.put(url, auth=jira_auth, json=data, timeout=30)

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

    def listTickets(self, project: str):
        logging.warning(
            "JiraTool.listTickets() is deprecated and will be removed soon, use JiraTool.list_tickets()"
        )
        return self.list_tickets(project=project)

    def list_tickets(self, project: str):
        """
        Prints all the tickets in a given project.

        Args:
            project: Which JIRA project to list
        """
        for singleIssue in self.connection.search_issues(
            jql_str=f"project = {project}"
        ):
            print(
                f"{singleIssue.key} {singleIssue.fields.summary} {singleIssue.fields.reporter.displayName}"
            )

    def getPriorityDict(self):
        logging.warning(
            "JiraTool.getPriorityDict() is deprecated and will be removed soon, use JiraTool.get_priority_dict()"
        )
        return self.get_priority_dict()

    def get_priority_dict(self):
        """
        Priorities can be altered by the local JIRA administrator.

        Returns:
            dictionary of all the priorities on a server and their IDs
        """
        raw_priorities = self.connection.priorities()
        priority_data = {}

        for priority in raw_priorities:
            logging.debug(f"{priority.name} : {priority.id}")
            priority_data[priority.name] = priority.id
        return priority_data

    def getTicket(self, ticket: str):
        logging.warning(
            "JiraTool.getTicket() is deprecated and will be removed soon, use JiraTool.get_ticket()"
        )
        return self.get_ticket(ticket=ticket)

    def get_ticket(self, ticket: str):
        """
        Peel a ticket out of JIRA

        Args:
            ticket: Which ticket to load

        Returns:
            JIRA issue object
        """
        issue = self.connection.issue(ticket)
        return issue

    def getTicketDict(self, project: str):
        logging.warning(
            "JiraTool.getTicketDict() is deprecated and will be removed soon, use JiraTool.get_ticket_dict()"
        )
        return self.get_ticket_dict(project=project)

    def get_ticket_dict(self, project: str):
        """
        Get all the JIRA tickets in a project. This is slow.

        Args:
            project: Which project to read from

        Returns:
            dict containing dictionaries for every ticket in the project, keyed by their ID.
        """
        tickets = {}
        for singleIssue in self.connection.search_issues(
            jql_str=f"project = {project}"
        ):
            tickets[singleIssue.key] = singleIssue
            logging.debug(f"{singleIssue.key} : {singleIssue}")
            logging.debug(f"{singleIssue.key} : fields {singleIssue.fields}")
            logging.debug(f"dumpObj(singleIssue : {dump_object(singleIssue)}")
            logging.debug(" ")
        return tickets

    def transitionTicket(self, ticket: str, state: str, comment: str = None):
        logging.warning(
            "JiraTool.getTicket() is deprecated and will be removed soon, use JiraTool.get_ticket()"
        )
        return self.transition_ticket(ticket=ticket, state=state)

    def transition_ticket(self, ticket: str, state: str, comment: str = None):
        """
        Transition a ticket to a new state.

        This is dangerous because the API doesn't enforce any transition
        constraints in the project's workflows.

        Sometimes workflows get can have states that can't be transitioned out
        of, so it's nice to have this available to pry tickets out of the
        dead-end states.

        Args:
            ticket: Which ticket to transition.
            state: What state to transition ticket to.
            comment: What comment to add to the ticket during transition.

        Raises:
            ValueError if state is not an available transition for ticket

        Returns:
            Result of the attempted ticket transition
        """
        issue = self.connection.issue(ticket)
        available_transitions = self.ticket_transitions(ticket=ticket)

        if state in available_transitions:
            logging.info(f"Transitioning issue {ticket} to state {state}")
            if comment:
                self.addComment(ticket=ticket, comment=comment)
            return self.connection.transition_issue(issue, available_transitions[state])
        else:
            raise ValueError(
                f"{ticket} does not have {state} as an available transition. Perhaps your user doesn't have privilege for that?"
            )

    # debug tools

    @lru_cache(maxsize=128)
    def customfield_human_names(self, ticket: str):
        """
        Get the human names for a ticket's custom fields.

        JIRA's API won't let you get the custom field data from an issue
        type because that would be too logical. Instead, you have to read
        them from an existing ticket of the type, which encourages people
        to keep golden tickets lying around.

        Instead of winning a trip to Wonka's factory, all you get for a
        golden ticket is more aggravation from JIRA when someone inevitably
        deletes them.

        Args:
            ticket: which ticket to load custom field data from

        Returns:
            dict containing customfield -> human name mappings
        """
        issue = self.get_issue_data(ticket)
        logging.debug(f"issue: {issue}")
        meta = self.get_issue_metadata(ticket=ticket)
        fields = meta["fields"]
        logging.debug(f"fields: {fields.keys()}")

        allfields = self.connection.fields()
        name_map = {
            self.connection.field["name"]: self.connection.field["id"]
            for self.connection.field in allfields
        }
        logging.debug(f"name_map: {name_map}")
        return name_map

    def vivisect(self, ticket_id: str):
        """
        Vivisect a ticket so we can figure out what attributes are visible
        via the module's API.

        Args:
            ticket_id: Which ticket to vivisect
        """
        ticket = self.get_ticket(ticket=ticket_id)
        print(f"ticket: {ticket}")
        print(f"Issue type: {ticket.fields.issuetype.name}")
        print("ticket transitions available:")
        for transition in self.connection.transitions(ticket):
            print(f"  {transition}")
        print()
        print(f"ticket.fields.issuetype: {ticket.fields.issuetype}")
        print(f"ticket.fields.issuelinks: {ticket.fields.issuelinks}")
        print(f"ticket.fields.issuelinks dump: {dump_object(ticket.fields.issuelinks)}")
        print()
        print(f"ticket.fields: {ticket.fields}")
        print()
        print(f"dir(ticket): {dir(ticket)}")
        print()
        print(f"ticket.fields (dump): {dump_object(ticket.fields)}")

    # Internal helpers
    def set_template_ticket(self, ticket: str = ""):
        """
        If a custom field only allows specific values, JIRA won't let us read
        those allowed values for a custom field from an issue type, only from
        an actual issue.

        If we want to assign values then, we need to know what issue to read
        the allowed list from, and it's less painful to assign that to the
        JIRA object than constantly pass a ticket argument around.

        With a well engineered API, you wouldn't have to do this. You'd
        assign a value to a field, and if it wasn't an allowed value, the
        server would return an error.

        JIRA's API on the other hand, is a dumpster fire and forces the user
        to care about internal implementation details.

        If a custom field is constrained to a list of values - let's use issue
        severity as an example, you first have to load JIRA's value mappings
        to integer ids. And those integers aren't even necessarily sequential.

        For example, here's a custom field where we might store dumpster color.

        "customfield_867": {
            "1 - grey": "5309",
            "2 - green": "16243",
            "3 - blue": "337",
            "4 - rust": "10967",
        }

        It's more stupid than it appears at first glance - those values can
        _change_ if you add or edit those values, which leads me to believe
        they're row numbers in a table somewhere - not even unique ids, just
        the row number.

        But wait, it's even more stupid than that - they can change if you edit
        _other_ custom fields in that issue type. No, really.

        Args:
            ticket: Which ticket to read template values from.
        """
        self.template_ticket = ticket

    def ticketTransitions(self, ticket: str):
        logging.warning(
            "JiraTool.ticketTransitions() is deprecated and will be removed soon, use JiraTool.ticket_transitions()"
        )
        return self.ticket_transitions(ticket=ticket)

    def ticket_transitions(self, ticket: str):
        """
        Find the available transitions for a given ticket.

        JIRA won't let you read these from an issue type, only an existing
        ticket.

        Args:
            ticket: Which ticket to scrape the transitions from

        Returns:
            dictionary keyed by transition name where the values are
            transition ids.
        """
        # Map the names to ids so the caller can use a human-understandable
        # name instead of having to track down the id.
        transitions = {}
        for t in self.connection.transitions(ticket):
            logging.debug(f"Found transition '{t['name']}, id {t['id']}")
            transitions[t["name"]] = t["id"]
        logging.debug(f"Transition lookup table: {transitions}")
        return transitions

    @lru_cache(maxsize=128)
    def load_customfield_allowed_values(self, ticket: str):
        """
        Get the allowed values for all custom fields on a ticket

        JIRA isn't very forgiving about ticket values, so provide a way to
        extract what it's expecting to find in a given custom field.

        We need this when setting menu type custom fields.

        Args:
            ticket: which ticket to scrape for values

        Returns:
            dictionary of allowed values for each custom field on a ticket,
            keyed by customfield_XXXX
        """
        logging.debug(f"connection: {self.connection}")

        issue = self.get_issue_data(ticket)
        logging.debug(f"issue: {issue}")

        meta = self.get_issue_metadata(ticket=ticket)

        allowed = {}
        fields = meta["fields"]
        logging.debug(f"fields: {fields.keys()}")
        for field in fields:
            logging.debug(f"Scanning {field}")
            if "allowedValues" in fields[field]:
                logging.info(
                    f"Field {field} has an allowedValues list, converting to dict"
                )
                logging.debug(f"Found {fields[field]['allowedValues']}")
                data = {}
                for opt in fields[field]["allowedValues"]:
                    if ("value" in opt) and ("id" in opt):
                        data[opt["value"]] = opt["id"]
                        logging.debug(f"Setting data['{opt['value']}'] to {opt['id']}")
                allowed[field] = data
        return allowed

    def _create_choice_field_entry(
        self, custom_field: str, value: str, ticket: str = ""
    ) -> dict:
        """
        Create a field entry for a choice field. We break this out so we
        can use it in both single field update calls and when we're updating
        multiple fields at once to minimize JIRA notifications

        Args:
            ticket: ticket to update
            custom_field: field to update
            value: value to assign

        Returns:
            dict with field data
        """
        if not ticket:
            ticket = self.template_ticket
        logging.debug(f"loading id map for {custom_field}...")
        value_mapping = self.allowed_values_for_field(
            ticket=ticket, custom_field=custom_field
        )
        entry = {"id": value_mapping[value], "value": value}
        logging.debug(f"entry: {entry}")
        return entry

    def _update_choice_field(self, custom_field: str, value: str, ticket: str) -> None:
        """
        Update a choice-style field

        Args:
            ticket: ticket to update
            custom_field: field to update
            value: value to assign

        Returns:
            update results
        """
        try:
            issue = self.get_ticket(ticket=ticket)
            logging.debug("Updating issue: %s", issue)
            logging.debug(
                f"Updating choice data, setting '{custom_field}' to '{value}'"
            )
            entry = self._create_choice_field_entry(
                ticket=ticket, custom_field=custom_field, value=value
            )
            fields = {custom_field: entry}
            logging.critical("Updating using %s", fields)
            return issue.update(fields=fields)
        except Exception as jiraConniption:
            logging.exception(jiraConniption)

    def updateFieldDict(
        self,
        custom_field: str,
        field_type: str,
        fields: dict = None,
        value=None,
        child_data=None,
    ):
        logging.warning(
            "JiraTool.updateFieldDict() is deprecated and will be removed soon, use JiraTool.update_field_dict()"
        )
        return self.update_field_dict(
            custom_field=custom_field,
            field_type=field_type,
            fields=fields,
            value=value,
            child_data=child_data,
        )

    def update_field_dict(
        self,
        custom_field: str,
        field_type: str,
        fields: dict = None,
        value=None,
        child_data=None,
    ):
        """
        Update the optional fields dictionary argument with an entry for the
        custom field & value specified. We create a blank fields dictionary if
        one is not provided.

        Args:
            custom_field: Which custom field to set
            field_type: What type is the field? JIRA makes us update them
                differently
            fields: An optional dictionary containing fields we've already set
            value: What value to assign to custom_field
            child_data: Some JIRA custom field types require two values, not
                just one.

        Returns:
            dictionary of field data
        """
        if not fields:
            fields = {}

        if field_type.lower() == "array" or field_type.lower() == "list":
            if custom_field not in fields:
                fields[custom_field] = []
                logging.debug(
                    "%s not found in fields, creating empty list", custom_field
                )

            if isinstance(value, list):
                for v in value:
                    logging.debug("Appending %s to %s", v, fields[custom_field])
                    fields[custom_field].append(v)
                    logging.debug("%s is now %s", custom_field, fields[custom_field])
            else:
                logging.debug("Appending %s to %s", value, fields[custom_field])
                fields[custom_field].append(value)
                logging.debug("%s is now %s", custom_field, fields[custom_field])

        if field_type.lower() == "choice":
            fields[custom_field] = {"value": value}

        if field_type.lower() == "multi-select":
            if custom_field not in fields:
                logging.debug(
                    "%s not found in fields, creating empty list", custom_field
                )
                fields[custom_field] = []
            if isinstance(value, list):
                for v in value:
                    logging.debug("Appending %s to %s", v, fields[custom_field])
                    fields[custom_field].append({"value": v})
            else:
                fields[custom_field].append({"value": value})

        if field_type.lower() == "menu" or field_type.lower() == "dropdown":
            # Suck abounds.
            #
            # JIRA dropdown field value menus are an aggravating sharp edge.
            # If you have a predefined list of menu items, you can't just
            # shovel in a string that corresponds to one of those defined
            # menu items. JIRA isn't smart enough to compare that string to
            # it's list of allowed values and use it if it's a valid option.
            #
            # Instead, you have to figure out what id that corresponds to, and
            # set _that_. Along with the damn original value, of course.
            entry = self._create_choice_field_entry(
                ticket=self.template_ticket, custom_field=custom_field, value=value
            )
            fields[custom_field] = entry

        if field_type.lower() == "parent":
            fields[custom_field] = {
                "value": value,
                "child": {"value": child_data},
            }

        if field_type.lower() == "priority":
            fields[custom_field] = {"name": value}

        if field_type.lower() == "string" or field_type.lower() == "str":
            fields[custom_field] = value

        logging.debug("Set data[%s] to %s", custom_field, fields[custom_field])
        return fields

    def add_issue_label(self, ticket: str = None, labels=None):
        """
        Add a label or labels to a ticket.

        Args:
            ticket: what ticket to add the label(s) to
            labels: either a str or a list of str
        """

        if not (isinstance(labels, list) or isinstance(labels, str)):
            raise ValueError("labels must be a str or a list of strings")
        issue = self.get_ticket(ticket=ticket)
        if isinstance(labels, str):
            labels = [labels]
        if isinstance(labels, list):
            logging.debug(f"labels = {labels}")
            for lbl in labels:
                if isinstance(lbl, str):
                    # JIRA is slow, so eliminate unnecessary calls to the API
                    if lbl not in issue.fields.labels:
                        issue.fields.labels.append(lbl)
                else:
                    raise ValueError(
                        f"Attempted to add labels {labels} from {ticket}, but {lbl} is not type str"
                    )
        return issue.update(fields={"labels": issue.fields.labels})

    def get_issue_labels(self, ticket: str = None):
        """
        Get labels for an issue

        Args:
            ticket: str of ticket to get labels for
        """
        issue = self.get_ticket(ticket=ticket)
        return issue.fields.labels

    def remove_issue_label(self, ticket: str = None, label=None):
        """
        Remove a label or list of labels from an issue

        Args:
            ticket: what ticket to remove the label(s) from
            labels: either a str or a list of str
        """
        if not (isinstance(label, list) or isinstance(label, str)):
            raise ValueError("label must be a str or a list of strings")
        issue = self.get_ticket(ticket=ticket)
        if isinstance(label, str):
            label = [label]

        if isinstance(label, list):
            for lbl in label:
                if isinstance(lbl, str):
                    # if the label isn't present, we don't want to error
                    if lbl in issue.fields.labels:
                        issue.fields.labels.remove(lbl)
                    else:
                        logging.warning(
                            f"Attempted to remove label {lbl} but it is not in {ticket}'s labels: {issue.fields.labels}"
                        )
                else:
                    logging.warning(f"label: {label}")
                    logging.warning(f"type: {type(label)}")
                    raise ValueError(
                        f"Attempted to remove labels {label} from {ticket}, but {lbl} is not type str"
                    )
        return issue.update(fields={"labels": issue.fields.labels})

    def jql(self, jql: str = None):
        """
        Return issues matching a JQL query

        Args:
            jql: A string containing a JQL query
        """
        logging.debug(f"JQL: {jql}")
        results = self.connection.search_issues(jql)
        logging.debug(f"QUERY RESULTS: {results}")
        return results
