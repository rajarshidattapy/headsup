import argparse
from getpass import getpass

from .config import Config
from .docker import Docker

class CLI:
  def __init__(self):
    parser = argparse.ArgumentParser(description='Hydra CLI')
    parser.add_argument('--version', action='version', version='hydra-cli 0.0.4')
    parser.add_argument('-C', '--config-dir', help='Specify the configuration directory', default=None, type=str, required=False)
    subparsers = parser.add_subparsers(dest='command', help='Subcommands')

    parser_setup = subparsers.add_parser('setup', help='Run initial interactive setup')
    parser_setup.add_argument('--short', help='Prompt for token only', action='store_true')

    parser_start = subparsers.add_parser('start', help='Start the service')
    parser_start.add_argument('-p', '--port', help='Port to run the service on', default=None, type=int, required=False)
    parser_start.add_argument('--attach', help='Stay attached (prints logs)', action='store_true')

    subparsers.add_parser('stop', help='Stop the service')

    parser_restart = subparsers.add_parser('restart', help='Restart the service')
    parser_restart.add_argument('-p', '--port', help='Port to run the service on', default=None, type=int, required=False)
    parser_restart.add_argument('--attach', help='Stay attached (prints logs)', action='store_true')

    parser_connect = subparsers.add_parser('connect', help='Connect to the service using psql')
    parser_connect.add_argument('--start', help='Start the service if it is not running', action='store_true')

    subparsers.add_parser('config', help='Show current configuration')

    subparsers.add_parser('teardown', help='Interactively remove configuration and/or data files')

    subparsers.add_parser('help', help='Show this help information')

    self.parser = parser


  def parse(self):
    args = self.parser.parse_args()

    if args.command == 'start':
      self.start(args)
    elif args.command == 'stop':
      self.stop(args)
    elif args.command == 'restart':
      self.stop(args)
      self.start(args)
    elif args.command == 'connect':
      self.connect(args)
    elif args.command == 'setup':
      self.setup(config_dir=args.config_dir, short=args.short)
    elif args.command == 'teardown':
      self.teardown(args)
    elif args.command == 'config':
      self.config(args)
    elif args.command == 'help':
      self.parser.print_help()
    else:
      self.commandless(args)


  def start(self, args):
    config = Config(config_dir=args.config_dir, port=args.port)
    # you can pass port in, but you _always_ need to run setup first in order to set the token
    docker = self.init_docker(config)
    if docker is None:
      return
    if docker.is_running():
      return print('Service is already running.')
    docker.start(detach=not args.attach)
    config.save()


  def stop(self, args):
    config = Config(config_dir=args.config_dir)
    docker = self.init_docker(config)
    if docker is None:
      return
    docker.stop()


  def connect(self, args):
    config = Config(config_dir=args.config_dir)
    docker = self.init_docker(config)
    if docker is None:
      return
    docker.connect(args.start)


  def config(self, args):
    config = Config(config_dir=args.config_dir)
    config = self.init_config(config)
    if config is None:
      return
    print('Configuration')
    print('===========================')
    print(f"Port: {config.port}")
    print(f"Username: {config.postgres_user}")
    print(f"Password: {config.postgres_password}")
    print(f"Database: postgres")
    print(f"Connection URL: postgresql://{config.postgres_user}:{config.postgres_password}@localhost:{config.port}/postgres")
    print(f"psql command: PGPASSWORD={config.postgres_password} psql -h localhost -U {config.postgres_user} -p {config.port} postgres")
    print(f"CLI configuration directory: {config.config_dir}")

    print('\nPlease note:')
    print('* The password is what was stored at the time of setup.If the password has been changed')
    print('  in the database, or changed in the configuration after the database was created, it')
    print('  will not be reflected here.')
    print('* Only the default database, postgres, is supported with Hydra Cloud at this time.')


  def setup(self, config_dir, short=False):
    current_config = Config(config_dir=config_dir)
    current_config.load()
    current_config.set_defaults()

    print('Visit https://start.hydra.so/token to get your token.')
    input_token = True
    if current_config.token and current_config.token.strip() != '':
      change_token = input("You already have a token saved. Do you want to change your token? [y/N] ").strip()
      if change_token.lower() != 'y':
        token = current_config.token
        input_token = False

    if input_token:
      token = ''
      while token.strip() == '':
        token = getpass("Enter your token: ")


    if not short:
      print('\nOptional configuration')
      print('===========================')

      port = None
      while port is None:
        port = input(f"Port to run the service on [{current_config.port}]: ").strip()
        if port == '':
          port = current_config.port
        try:
          port = int(port)
        except ValueError:
          port = None
        if port > 65535 or port < 1024:
          port = None
        if port is None:
          print('Invalid port, must be a number between 1024 and 65535')

      user = input(f"Postgres superuser [{current_config.postgres_user}]: ").strip()
      if user == '':
        user = current_config.postgres_user

      print('\nNote: Once the database has been created, changing the password setting will have no effect.')
      password = input(f"Password for superuser [{current_config.postgres_password}]: ").strip()
      if password == '':
        password = current_config.postgres_password
    else:
        port = current_config.port
        user = current_config.postgres_user
        password = current_config.postgres_password


    config = Config(config_dir=config_dir, token=token, port=port, postgres_user=user, postgres_password=password)
    config.init()
    config.save()
    return config


  def commandless(self, args):
    config = Config(config_dir=args.config_dir)
    if not config.is_loadable():
      config = self.setup(config_dir=args.config_dir, short=True)

    docker = self.init_docker(config)
    if docker is None:
      return
    docker.connect(start=True)


  def teardown(self, args):
    # do not init this config!
    config = Config(config_dir=args.config_dir)
    delete_config = input('Delete configuration files [y/N]: ')
    if delete_config.lower() == 'y':
      config.teardown()
    delete_docker = input('Delete Docker data volume [y/N]: ')
    if delete_docker.lower() == 'y':
      # using an un-init / 'bad' config is OK here because we're not using start
      docker = Docker(config)
      if not docker.is_docker_available():
        self.handle_docker_not_available(install_prompt=False)
      else:
        docker.teardown()


  def handle_setup_not_run(self):
    print('You must run `hydra setup` first.')


  def handle_config_incomplete(self):
    print('Configuration is incomplete. Please run `hydra setup`.')


  def handle_docker_not_available(self, install_prompt = True):
    print('Docker engine is not available. Please check if Docker is running.')
    if install_prompt:
      print('\nNeed to install Docker? Download Docker from:')
      print('https://docs.docker.com/engine/install/')


  def init_config(self, config, print_errors=True):
    if not config.is_loadable():
      if print_errors:
        self.handle_setup_not_run()
      return None
    config.init()
    if config.is_incomplete():
      if print_errors:
        self.handle_config_incomplete()
      return None
    return config


  def init_docker(self, config):
    config = self.init_config(config)
    if config is None:
      return None
    docker = Docker(config)
    if not docker.is_docker_available():
      self.handle_docker_not_available()
      return None
    return docker
