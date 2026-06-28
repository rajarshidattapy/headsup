from hydra_cli.cli import CLI

def main():
  try:
    CLI().parse()
  except (KeyboardInterrupt, EOFError):
    exit
