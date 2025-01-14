
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
        case "key":
            crypto = cli_args.crypto
            endpoint = "create-key/"
            resp = requests.get(create_url(service_address, endpoint), json={
                "crypto": crypto,
            })
            data = resp.json()
            flush_json(data)
            if cli_args.outfile:
                with open(os.path.join(storage, cli_args.outfile), "w") as f:
                    json.dump(data, f, indent=4)
        case "did":
            method = cli_args.method
            endpoint = "create-did/"
            options = {"method": method}
            with open(os.path.join(storage, cli_args.infile), "r") as f:
                loaded_key = json.load(f)["key"]
            options["publicJwk"] = loaded_key["publicJwk"]
            resp = requests.get(create_url(service_address, endpoint),
                                json=options)
            data = resp.json()
            flush_json(data)
            if cli_args.outfile:
                with open(os.path.join(storage, cli_args.outfile), "w") as f:
                    json.dump(data, f, indent=4)


def main_issue():
    subcommand = cli_args.issue_subcommand

    match subcommand:
        case "vc":
            issuer = cli_args.issuer
            with open(cli_args.key) as f:
                jwk = json.load(f)["key"]["privateJwk"] # TODO
            kid = cli_args.kid
            subject = cli_args.subject
            endpoint = "issue-credential/"
            resp = requests.get(create_url(service_address, endpoint), json={
                "issuer": issuer,
                "subject": subject,
                "jwk": jwk,
                "kid": kid,
            })
            data = resp.json()
            flush_json(data)
        case "vp":
            raise NotImplementedError


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

    ### create key
    create_key = create_subcommand.add_parser("key",
                        help="Create key")
    create_key.add_argument("--crypto", type=str, metavar="SYSTEM",
                        choices=["rsa", "RSA", "ES256K", "secp256k1"],
                        default="ES256K", help="Underlying cryptosystem")
    create_key.add_argument("--out", type=str, metavar="OUTFILE",
                        dest="outfile",
                        help="Save key inside .api-client-storage")

    ### create did
    create_did = create_subcommand.add_parser("did",
                        help="Create DID")
    create_did.add_argument("--key", type=str, metavar="INFILE",
                        required=True, dest="infile",
                        help="Key to use from .api-client-storage")
    create_did.add_argument("--method", type=str, metavar="METHOD",
                        choices=["key", "ebsi"],
                        default="ebsi", help="DID method")
    create_did.add_argument("--out", type=str, metavar="OUTFILE",
                        dest="outfile",
                        help="Save DID inside .api-client-storage")

    ## resolve
    resolve = commands.add_parser("resolve", help="Resolve DID")

    ### resolve did
    resolve.add_argument("did", type=str, metavar="<DID>",
                         help="DID to resolve")

    ## issue
    issue = commands.add_parser("issue", help="Issuance actions")
    issue_subcommand = issue.add_subparsers(dest="issue_subcommand")

    ### issue vc
    issue_vc = issue_subcommand.add_parser("vc",
                        help="Issue verifiable credential")
    issue_vc.add_argument("--issuer", type=str, metavar="<DID>",
                        default="did:ebsi:zxaYaUtb8pvoAtYNWbKcveg",
                        help="Issuer DID")
    issue_vc.add_argument("--key", type=str, metavar="<FILE>",
                        required=True,
                        help="Issuer's private JWK")
    issue_vc.add_argument("--kid", type=str, metavar="<KID>",
                        default="CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc",
                        help="Issuer's JWK kid")
    issue_vc.add_argument("--subject", type=str, metavar="<DID>",
                        default="did:ebsi:z25a23eWUxQQzmAgnD9srpMM",
                        help="Subject DID")

    ### issue vp
    issue_vp = issue_subcommand.add_parser("vp",
                        help="Issue verifiable presentation")
    # TODO: Options


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
        case "issue":
            main_issue()



if __name__ == "__main__":
    main()
