"""Execute every supported shell step of a shared composite action, fail closed."""
import os
import subprocess
import sys
from pathlib import Path

import yaml


def steps(path):
    action = yaml.safe_load(Path(path).read_text())
    assert action['runs']['using'] == 'composite'
    result = action['runs']['steps']
    for step in result:
        if set(step) - {'name', 'shell', 'run'} or step.get('shell') != 'bash':
            raise ValueError(f"Unsupported composite step: {step.get('name')}")
        if '${{' in step['run']:
            raise ValueError('Actions expressions require explicit local handling')
    return result


if __name__ == '__main__':
    for step in steps(sys.argv[1]):
        print(f"==> {step.get('name', 'action step')}", flush=True)
        subprocess.run(['bash', '-euo', 'pipefail', '-c', step['run']], check=True,
                       env=os.environ)
