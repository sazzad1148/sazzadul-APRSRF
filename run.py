#!/usr/bin/env python3
"""sazzad007 -- thin entry point: `python3 run.py -d example.com --profile balanced`."""
import sys

from subdomain_recon.cli import main

if __name__ == "__main__":
    sys.exit(main())
