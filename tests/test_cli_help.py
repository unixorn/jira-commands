from jira_commands.cli.common import base_cli_parser


def test_password_help_names_password_not_username():
    parser = base_cli_parser(description="help check")
    help_text = parser.format_help()
    assert "--password" in help_text
    for action in parser._actions:
        if "--password" in action.option_strings:
            assert "password" in (action.help or "").lower()
            assert "username" not in (action.help or "").lower()
