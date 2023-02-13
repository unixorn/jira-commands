# jira-commands

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/license/apache2-0-php/)
[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2Funixorn%2Fjira-commands%2Fbadge%3Fref%3Dmain&style=plastic)](https://actions-badge.atrox.dev/unixorn/jira-commands/goto?ref=main)
![Megalinter](https://github.com/unixorn/jira-commands/actions/workflows/mega-linter.yml/badge.svg)
![PyPI - Format](https://img.shields.io/pypi/format/jira-commands?style=plastic)

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
## Table of Contents

- [Scripts](#scripts)
- [Configuration](#configuration)
  - [Basic Authentication](#basic-authentication)
  - [OAuth Authentication](#oauth-authentication)
  - [PAT authentication](#pat-authentication)
- [Installation](#installation)
  - [Run via docker / nerdctl](#run-via-docker--nerdctl)
  - [Direct pip install](#direct-pip-install)
  - [ZSH plugin](#zsh-plugin)
    - [zgenom](#zgenom)
    - [Antigen](#antigen)
    - [oh-my-zsh](#oh-my-zsh)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

Some command-line tools for interacting with JIRA.

## Scripts

All of these scripts support `--help` to get a detailed list of command line options.

| Name                         | Description                                           |
| -----------------------------| ----------------------------------------------------- |
| `jc` | Main driver. Will run all the other commands inside a docker container for you. |
| `jc assign ticket` / `jc ticket assign` | Assign a ticket to someone. |
| `jc close ticket` / `jc ticket close` | Close a ticket |
| `jc comment on ticket` / `jc ticket comment` | Comment on a ticket |
| `jc create ticket` / `jc ticket create` | Create a ticket. You will need|
| `jc custom field allowed values` | List a custom field's allowed values since JIRA isn't forthcoming about them. |
| `jc examine ticket` / `jc ticket examine` | Detailed dump of a ticket and all its custom field names |
| `jc extract customfield mappings` | Extract the custom field mappings from an issue into a file |
| `jc get link types` | Prints the names of all link types defined on your JIRA instance. |
| `jc get priority ids` | Prints the names of all ticket priorities defined on your JIRA instance. |
| `jc link tickets` / `jc ticket link` | Link two tickets. Use `jc get link types` to see what link names are defined on your JIRA server. Case matters. |
| `jc list project tickets` | List open tickets in a given JIRA project |
| `jc list ticket transitions` / `jc ticket transition list` | See the availale transitions for a given ticket. |
| `jc transition ticket to` / `jc ticket transition set` | Transition a ticket to another state. Use `jc list ticket transitions` to see which are available  |
| `jc vivisect ticket` / `jc ticket vivisect` | Detailed dump of a ticket to find out all the custom field names and other innards. |

The `jc` program is the main driver script and will find the subcommands, so you can do `jc ticket comment --ticket ABC-123 --comment 'foo bar baz'` and it will find the `jc-ticket-comment` script and run it with the `--ticket` and `--comment` arguments.

If you're using the docker method, `jc` will automatically run the subcommands inside a container for you. If you've installed via pip, it'll find the commands where they were installed in your `$PATH`.

## Configuration

The `jc` commands all read settings from `~/.jira-commands/jira.yaml`. Settings in the file can be overridden by specifying command-line options.

### Basic Authentication

I'm setting my username and jira server in the example configuraation file below. The tools will ask for my password when I run them.

```yaml
jira_server: https://jira.example.com
username: YOUR_JIRA_USER
```

You can specify a `password` key but it's a terrible idea.

### OAuth Authentication

Here's an example settings file for oauth authentication. Add `--auth=OAUTH` to use oath instead of basic authentication.

```yaml
jira_server: https://jira.example.com/
oauth_access_token: ABCDabcdABCDabcdABCDabcdABCDabcd
oauth_access_token_secret: ABCDabcdABCDabcdABCDabcdABCDabcd
oauth_consumer_key: OAUTH_CONSUMER_KEY_ID
oauth_private_key_pem_pathL: /path/to/pem/file
username: YOUR_JIRA_USER
```

### PAT authentication

Here's an example settings file for PAT authentication.

```yaml
username: YOUR_JIRA_USER
pat_token: xyzzyAbc123
jira_server: https://jira.example.com/
```

## Installation

### Run via docker / nerdctl

This is the recommended way to use the `jc` commands, and how it will be run if you use one of the ZSH frameworks detailed below.

If you're not using a ZSH framework, clone this repository and add its `bin` directory to your `$PATH`. It contains a `jc` script that will detect whether you have `nerdctl` or `docker` and if it finds them, map `~/jira-commands` (and the configuration file there) into a volume in the `jira-commands` container and run the tools inside the container.

### Direct pip install

`sudo pip install jira-commands` will install the command-line tools via `pip`. This may cause compatibility annoyances with other python tools on your system, so there's a `docker`/`nerdctl` option as well.

### ZSH plugin

The tooling has been packaged as a ZSH plugin to make using it as easy as possible for ZSH users.

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
