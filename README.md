# jira-commands

Some command-line tools for interacting with JIRA

- jc
- jc-ticket-assign
- jc-ticket-comment
- jc-ticket-comment-on-ticket
- jc-ticket-create
- jc-ticket-examine
- jc-ticket-print
- jc-ticket-transition-list
- jc-ticket-transition-set
- jc-ticket-vivisect

The`jc` main driver script will find the subcommands, so you can do `jc ticket comment --ticket ABC-123 --comment 'foo bar baz'` and it will find the `jc-ticket-comment` script and run it with the `--ticket` and `--comment` arguments.