import platformdirs
import toml
import os
import random, string
import socket


class Config:

  def __init__(self, token = None, config_dir = None, port = None, postgres_user = None, postgres_password = None):
    if config_dir is None:
      config_dir = platformdirs.user_data_dir('hydra-cli', 'hydra')

    # inputs
    self.config_dir = config_dir
    self.token = token
    self.port = port
    self.postgres_user = postgres_user
    self.postgres_password = postgres_password

    # private-ish variables
    self.postgres_config_filename = 'postgresql.conf'
    self.save_file = 'config.toml'


  def init(self):
    os.makedirs(self.config_dir, exist_ok=True, mode=0o700)

    # load will read config from disk but not overwrite current instance values
    self.load()

    # config file should have the port as an int, but just make sure
    if isinstance(self.port, str):
      self.port = int(self.port)

    # set any remaining unset values to their defaults
    self.set_defaults()

    self.write_postgres_config()


  def is_loadable(self):
    return os.path.exists(self.config_dir) and os.path.exists(self.path(self.save_file))


  def is_incomplete(self):
    return self.token is None or self.port is None or self.postgres_user is None or self.postgres_password is None


  def set_defaults(self):
    if not isinstance(self.port, int):
      self.port = self.find_random_open_port()
    if not isinstance(self.postgres_user, str) or self.postgres_user.strip() == '':
      self.postgres_user = 'postgres'
    if not isinstance(self.postgres_password, str) or self.postgres_password.strip() == '':
      self.postgres_password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))


  def find_random_open_port(self):
    try:
      port = random.randint(1024, 65535)
      attempts = 0
      while attempts < 10:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
          try:
            s.bind(("", port))
            return port
          except OSError:
            port = random.randint(1024, 65535)
            attempts += 1
      # we ran out of attempts, likely due to some restriction by the OS, so return a default
      return 65432
    # If we run into any other issues, return a default
    except:
      return 65432


  def write_postgres_config(self):
    with open(self.postgres_config(), 'w') as f:
      f.write('listen_addresses = \'*\'\n')
      f.write('shared_preload_libraries = \'pg_duckdb\'\n')
      if self.token is not None:
        f.write(f"duckdb.hydra_token = '{self.token}'\n")


  def postgres_config(self):
    return self.path(self.postgres_config_filename)


  def path(self, filename):
    return os.path.join(self.config_dir, filename)


  def save(self):
    with open(self.path(self.save_file), 'w') as f:
      toml.dump({
          'port': self.port,
          'postgres_user': self.postgres_user,
          'postgres_password': self.postgres_password,
          'token': self.token
        }, f)


  def teardown(self):
    try:
      os.remove(self.postgres_config())
    except FileNotFoundError:
      pass

    try:
      os.remove(self.path(self.save_file))
    except FileNotFoundError:
      pass

    try:
      # this ensures the directory is empty before trying to remove it. it should be empty unless
      # the user has manually added files to the config directory
      files = os.listdir(self.config_dir)
      if len(files) > 0:
        print('Config directory is not empty. Please check the contents and remove manually.')
        return False
      os.rmdir(self.config_dir)
    except FileNotFoundError:
      pass

    return True

  def load(self):
    config = self.read_config()
    if config is not None:
      for k in ['port', 'postgres_user', 'postgres_password', 'token']:
        if getattr(self, k) is None and k in config:
          setattr(self, k, config[k])


  def read_config(self):
    try:
      with open(self.path(self.save_file), 'r') as f:
        return toml.load(f)
    except FileNotFoundError:
      return None
