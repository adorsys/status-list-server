"""Read workflow values instead of maintaining duplicate local lists."""
import sys
from pathlib import Path
import yaml

jobs = yaml.safe_load(Path('.github/workflows/CI.yml').read_text())['jobs']
if sys.argv[1] == 'variants':
    for item in jobs['release-variant-checks']['strategy']['matrix']['variant']:
        print(item['features'])
elif sys.argv[1] == 'gated':
    missing = set(jobs) - {'ci-success'} - set(jobs['ci-success']['needs'])
    if missing:
        raise SystemExit(f'Jobs missing from ci-success.needs: {sorted(missing)}')
else:
    raise SystemExit('Unknown workflow query')
