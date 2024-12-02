
"""
CLI client for interacting with the ebsi-onboader API
"""

import argparse
import sys
import json

from urllib.parse import urljoin
from sys import stdout

import requests

service_address = None
cli_args = None


def create_url(address, endpoint, prefix=""):
    return urljoin(address, urljoin(prefix + "/", endpoint.lstrip("/")))

def flush_json(payload, indent=4, nojump=False):
    buff = json.dumps(payload, indent=indent)
    if nojump:
        buff = buff.replace(",\n", ", ").replace("[\n", "[").replace("\n]", "]")
    stdout.write(buff + "\n")


def main_fetch():
    subcommand = cli_args.fetch_subcommand

    match subcommand:
        case "info":
            endpoint = "info/"

    resp = requests.get(create_url(service_address, endpoint))
    data = resp.json()
    if not cli_args.suppress:
        flush_json(data)


def main_submit():
    subcommand = cli_args.fetch_subcommand

    match cli_args.submit_subcommand:
        case "did":
            raise NotImplemented

def main():
    prog = sys.argv[0]
    usage = "python %s [OPTIONS]" % prog
    epilog = "\n"
    description = __doc__
    epilog = ""
    parser = argparse.ArgumentParser(prog=prog,
                        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                        description=description,
                        epilog=epilog)

    # Options
    parser.add_argument("--host", type=str, default="localhost",
                        help="Service host")
    parser.add_argument("--port", type=int, default=3000,
                        help="Service port")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--verbose", action="store_true", default=False,
                        help="Display payload for POST requests")
    group.add_argument("--quiet", action="store_true", default=False,
                        help="Display no info at all. Overrides verbose")

    # Commands
    commands = parser.add_subparsers(dest="command")

    ## fetch
    fetch = commands.add_parser("fetch", help="GET requests")
    fetch.add_argument("--suppress", action="store_true", default=False,
                        help="Do not display JSON response")
    fetch_subcommand = fetch.add_subparsers(dest="fetch_subcommand")
    fetch_crypto = fetch_subcommand.add_parser("info",
                        help="Fetch service info")

    ## submit
    submit = commands.add_parser("submit", help="POST requests")
    submit_subcommand = submit.add_subparsers(dest="submit_subcommand")
    submit_did = submit_subcommand.add_parser("did",
                        help="Submit DID to onboard")

    global cli_args
    global service_address
    cli_args = parser.parse_args()
    service_address = f"http://{cli_args.host}:{cli_args.port}"

    match cli_args.command:
        case "fetch":
            main_fetch()
        case "submit":
            main_submit()



if __name__ == "__main__":
    main()
