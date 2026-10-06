"""Lets the tool run as `python -m phishing_triage`."""

import sys

from phishing_triage.cli import main

sys.exit(main())
