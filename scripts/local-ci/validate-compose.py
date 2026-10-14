"""Validate CI's Compose model without reading or printing developer secrets."""
import os
from pathlib import Path
import subprocess
import yaml

root = Path.cwd()
work = Path(os.environ['RUNNER_TEMP'])
model = yaml.safe_load((root / 'docker-compose.yml').read_text())
# CI runs without a developer .env file. Remove optional .env file references.
for service in model['services'].values():
    if 'env_file' in service:
        service['env_file'] = [entry for entry in service['env_file']
                               if (entry.get('path') if isinstance(entry, dict) else entry) != '.env']
path = work / 'compose.yaml'
path.write_text(yaml.safe_dump(model, sort_keys=False))
empty = work / 'empty.env'
empty.touch()
# Do not inherit shell values that could substitute secrets into the model.
env = {k: v for k, v in os.environ.items()
       if k in ('PATH', 'HOME', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG',
                'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'XDG_RUNTIME_DIR')}
env['GRAFANA_ADMIN_PASSWORD'] = 'placeholder-not-a-real-credential'
subprocess.run(['docker', 'compose', '--project-directory', str(root),
                '--env-file', str(empty), '-f', str(path), 'config', '--quiet'],
               env=env, check=True)
