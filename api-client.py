
"""
CLI client for interacting with the ebsi-onboader API
"""

import argparse
import sys
import json
import os

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


def main_resolve():
    did = cli_args.did
    endpoint = "resolve-did/"
    resp = requests.get(create_url(service_address, endpoint), json={
        "did": did
    })
    data = resp.json()
    flush_json(data)


def main_create():
    subcommand = cli_args.create_subcommand

    match subcommand:
        case "did":
            method = cli_args.method
            crypto = cli_args.crypto
            endpoint = "create-did/"
            resp = requests.get(create_url(service_address, endpoint), json={
                "crypto": crypto,
                "method": method,
            })
            data = resp.json()
            flush_json(data)
            if cli_args.out:
                with open(os.path.join(storage, cli_args.out), "w") as f:
                    json.dump(data, f, indent=4)


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
                        help="Display submitted payloads")
    group.add_argument("--quiet", action="store_true", default=False,
                        help="Display no info at all. Overrides verbose")

    # Commands
    commands = parser.add_subparsers(dest="command")

    ## fetch
    fetch = commands.add_parser("fetch", help="Fetch resource actions")
    fetch.add_argument("--suppress", action="store_true", default=False,
                        help="Do not display JSON response")
    fetch_subcommand = fetch.add_subparsers(dest="fetch_subcommand")

    ## fetch info
    fetch_info = fetch_subcommand.add_parser("info",
                        help="Fetch service info")

    ## create
    create = commands.add_parser("create", help="Creation actions")
    create_subcommand = create.add_subparsers(dest="create_subcommand")

    ### create did
    create_did = create_subcommand.add_parser("did",
                        help="Create DID")
    create_did.add_argument("--crypto", type=str, metavar="<SYSTEM>",
                        choices=["rsa", "RSA", "ES256K", "secp256k1"],
                        default="ES256K", help="Underlying cryptosystem")
    create_did.add_argument("--method", type=str, metavar="<METHOD>",
                        choices=["key", "ebsi"],
                        default="ebsi", help="DID method")
    create_did.add_argument("--out", type=str, metavar="<FILE>",
                        help="Save DID inside .api-client-storage")

    ## resolve
    resolve = commands.add_parser("resolve", help="Resolve DID")

    ### resolve did
    resolve.add_argument("did", type=str, metavar="<DID>",
                         help="DID to resolve")

    global cli_args
    global service_address
    global storage
    cli_args = parser.parse_args()
    service_address = f"http://{cli_args.host}:{cli_args.port}"
    storage =  "./.api-client-storage"  # TODO: Consider parametrizing this

    match cli_args.command:
        case "fetch":
            main_fetch()
        case "create":
            main_create()
        case "resolve":
            main_resolve()



if __name__ == "__main__":
    main()
