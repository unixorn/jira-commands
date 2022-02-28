# jira-commands

Some command-line tools for interacting with JIRA.

- jc
- jc-get-link-types
- jc-ticket-assign
- jc-ticket-close
- jc-ticket-comment
- jc-ticket-comment-on-ticket
- jc-ticket-create
- jc-ticket-examine
- jc-ticket-link
- jc-ticket-print
- jc-ticket-transition-list
- jc-ticket-transition-set
- jc-ticket-vivisect

The`jc` main driver script will find the subcommands, so you can do `jc ticket comment --ticket ABC-123 --comment 'foo bar baz'` and it will find the `jc-ticket-comment` script and run it with the `--ticket` and `--comment` arguments.

## Configuration

The `jc` commands all read settings from `~/.jira-commands/jira.yaml`. Settings in the file can be overriden by specifying command-line options.

I'm setting my username and jira server in the example below. The tools will ask for my password when I run them.

```yaml
username: yourusername
jira_server: https://jira.example.com
```

You can specify a `password` key but it's a terrible idea.

## Installation

### Direct

`sudo pip install jira-commands` will install the command-line tools via `pip`. This may cause compatibility annoyances with other python tools on your system, so there's a `docker`/`nerdctl` option as well.

### Manually run via docker / nerdctl

If you're not using a ZSH framework, all you have to do is clone this repository and add its `bin` directory to your `$PATH`. It contains a `jc` script that will detect whether you have `nerdctl` or `docker` and if it finds them, map your configuration file into a volume in the `jira-commands` container and run the tools inside the container.

### ZSH plugin

#### zgenom

If you're using [Zgenom](https://github.com/jandamm/zgenom):

1. Add `zgenom load unixorn/jira-commands` to your `.zshrc` with your other plugins
2. `zgenom reset && zgenom save`

#### Antigen

If you're using [Antigen](https://github.com/zsh-users/antigen):

1. Add `antigen bundle unixorn/jira-commands` to your .zshrc where you've listed your other plugins.
2. Close and reopen your Terminal/iTerm window to refresh context and use the plugin. Alternatively, you can run `antigen bundle unixorn/jira-commands` in a running shell to have `antigen` load the new plugin.

#### oh-my-zsh

If you're using [oh-my-zsh](https://ohmyz.sh):

1. Clone the repository into a new `jira-commands` directory in oh-my-zsh's plugin folder:

    `git clone https://github.com/unixorn/jira-commands.git $ZSH_CUSTOM/plugins/jira-commands`

2. Edit your `~/.zshrc` and add `jira-commands` – same as clone directory – to the list of plugins to enable:

    `plugins=( ... jira-commands )`

3. Then, restart your terminal application to refresh context and use the plugin. Alternatively, you can source your current shell configuration:

    `source ~/.zshrc`
