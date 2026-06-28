# Installation

1. You must have Docker and Python 3 installed.
2. `pip install hydra-cli` (or as desired for your preferred Python environment)

# Getting Started

Just run `hydra` and we'll take care of the rest!

```
$ hydra
```

This will:

1. run `hydra setup` if needed
2. run `hydra connect --start`
   1. start the server
   2. open a psql shell
   3. stop the server and cleanup when you exit the shell

To exit the psql shell, use `exit`, `\q` or `^D`.

Now you're ready to [follow our quickstart guide](https://docs.hydra.so/intro/quickstart) to learn more about serverless
analytics with Hydra.

Any data stored in `duckdb` tables are stored in Hydra's cloud service. Data saved in Postgres (heap) tables will be
stored in a local Docker volume and is not persisted to the cloud.

# Commands

You can run `hydra help` for a list of commands, and `hydra COMMAND --help` to get help about any command.

```
$ hydra
 - runs setup if necessary, starts service, connects, then stops service
$ hydra setup
 - asks for token; optional port, username, password
$ hydra start
 - starts service
$ hydra stop
 - stops service
$ hydra restart
 - stops then starts the service
$ hydra connect
 - connects to service via psql
$ hydra connect --start
 - automatically starts and stops the service around a psql session
$ hydra config
 - prints stored config info
$ hydra teardown
 - prompts to delete configuration files
 - prompts to delete docker volume
$ hydra help
$ hydra --help
 - prints reference top-level information for the CLI
$ hydra COMMAND --help
 - prints helpful information about the command
```

# Configuration

Configuration is persistent. Once you specify your settings, it will remember what port you used. If would like to change
the settings, you can run `hydra setup` again. You can also change the port number at any time with `hydra start`.

## Configuration files

By default, configuration is saved to `hydra-cli` in your platform's user data directory:

* Mac OS X: `~/Library/Application Support/hydra-cli`
* Linux: `~/.local/share/hydra-cli`

You can specify a different configuration directory with `-C`/`--config-dir`, but you will need to pass this in with
every execution.

# Uninstalling

1. `hydra stop` removes the running container, if one remains.
2. `hydra teardown` will confirm removal of the configuration files and the Docker volume, respectively.
3. `pip uninstall hydra-cli` will remove the CLI itself.
