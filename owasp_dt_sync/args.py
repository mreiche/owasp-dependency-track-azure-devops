import argparse
import pathlib

from owasp_dt_sync.sync import handle_sync

def create_parser():
    parser = argparse.ArgumentParser(
        description="OWASP Dependency Track Azure DevOps Sync",
        exit_on_error=False
    )
    parser.add_argument("--apply", help="Set this flag to perform write actions on Findings and WorkItems", action='store_true', default=False)
    parser.add_argument("--cvss-min-score", help="Minimal CVSS score value of Findings to synchronize", default=None)
    parser.add_argument("--env", help="Environment file to load", type=pathlib.Path, default=None)
    parser.add_argument("--mapper", help="Custom mapper Python script", type=pathlib.Path, default=None)
    parser.add_argument("--template", help="Jinja2 template file path for WorkItems", type=pathlib.Path, default=None)
    parser.set_defaults(func=handle_sync)
    return parser
