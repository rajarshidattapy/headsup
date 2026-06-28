import docker
import subprocess
import shutil

from time import sleep

class Docker:

  def __init__(self, config):
    self.config = config
    self.client = self.init_client()
    self.image = 'hydradb/hydra-cli:latest'
    self.volume = 'hydra-cli_data'
    self.container = 'hydra-cli'


  def update_image(self):
    if isinstance(self.client, Exception):
      raise self.client

    image = self.client.images.list(name=self.image)
    if len(image) > 0:
      print(f"Updating image... ", end='', flush=True)
    else:
      print(f"Downloading image... ", end='', flush=True)

    self.client.images.pull(self.image)
    print("done.")


  def start(self, detach=True):
    if isinstance(self.client, Exception):
      raise self.client

    self.update_image()
    print(f"Starting service on port {self.config.port}... ", end='', flush=True)
    if not detach:
      print('\n')

    try:
      container = self.client.containers.run(
        image=self.image,
        name=self.container,
        detach=True,
        stdout=True,
        stderr=True,
        command="postgres -c 'config_file=/etc/postgresql/postgresql.conf'",
        ports={'5432/tcp': self.config.port},
        mounts=[
          docker.types.Mount('/etc/postgresql/postgresql.conf', self.config.postgres_config(), type='bind'),
          docker.types.Mount('/var/lib/postgresql/data', self.volume, type='volume')
        ],
        environment={
          "POSTGRES_USER": self.config.postgres_user,
          "POSTGRES_PASSWORD": self.config.postgres_password
        }
      )
      if not detach:
        for line in container.logs(stream=True):
          print(line.decode('utf-8').strip())
    except (docker.errors.ContainerError, docker.errors.APIError) as e:
      self.stop()
      print(e)
    except KeyboardInterrupt:
      print('\n')
      self.stop()

    if detach:
      print("done.")


  def stop(self, silent=False):
    if isinstance(self.client, Exception):
      raise self.client

    if not silent:
      print("Stopping service... ", end='', flush=True)

    found = False
    for container in self.client.containers.list(all=True, filters={'name': self.container}):
      container.stop()
      container.remove(v=False)
      found = True

    if not silent:
      if found:
        print("done.")
      else:
        print("service not found.")

    return found


  def connect(self, start=False, stop_if_started=True):
    if isinstance(self.client, Exception):
      raise self.client

    started = False
    if not self.is_running():
      if start:
        self.start()
        started = True
        print("Waiting for service to complete initialization... ", end='', flush=True)
        sleep(5)
        print("done.")
      else:
        print("Service is not running. Use --start to start the service automatically.")
        return

    # -- this method did not work as it did not allow for user input
    # container = self.client.containers.list(filters={'name': self.container})[0]
    # container.exec_run('psql', tty=True, stdin=True, stdout=True, stderr=True, detach=False)

    print('Starting psql. To exit psql, use `exit`, `\\q` or `Ctrl-D`.\n')
    docker = shutil.which('docker')
    if docker is None:
      print('`docker` cli command unavailable, trying `psql`...')
      psql = shutil.which('psql')
      if psql is None:
        print('`psql` unavailable.')
        print('Please ensure either `docker` or `psql` is installed and available on your PATH.')
      else:
        subprocess.run(
          [psql, '-h', 'localhost', '-p', str(self.config.port), '-U', self.config.postgres_user],
          shell=False,
          env={'PGPASSWORD': self.config.postgres_password}
        )
    else:
      subprocess.run(
        [docker, 'exec', '-it', 'hydra-cli', 'psql'],
        shell=False,
        env={'DOCKER_CLI_HINTS': 'false'})

    if stop_if_started and started:
      self.stop()


  def is_running(self):
    if isinstance(self.client, Exception):
      raise self.client

    return len(self.client.containers.list(filters={'name': self.container})) > 0


  def teardown(self):
    if isinstance(self.client, Exception):
      raise self.client

    # ensure not running and container is removed
    self.stop(silent=True)
    # prune with filter did not work, so find manually and call `remove`
    for volume in self.client.volumes.list():
      if volume.name == self.volume:
        volume.remove(force=True)


  def init_client(self):
    try:
      return docker.from_env()
    except Exception as e:
      return e


  def is_docker_available(self):
    return not isinstance(self.client, Exception)
