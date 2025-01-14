
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


def get_public_jwk(key_path):
    with open(key_path, "r") as f:
        jwk = json.load(f)
    kty = jwk["kty"]

    if kty == "RSA":
        return {
            "kty": kty,
            "n": jwk["n"],
            "e": jwk["e"],
        }
    elif kty == "EC":
        return {
            "kty": kty,
            "x": jwk["x"],
            "y": jwk["y"],
            "crv": jwk["crv"],
        }
    else:
        raise AssertionError(f"Unknown kty: {kty}")


def main_create():
    subcommand = cli_args.create_subcommand

    match subcommand:
        case "key":
            endpoint = "create-key/"
            resp = requests.get(create_url(service_address, endpoint), json={
                "alg": cli_args.alg,
            })
            data = resp.json()
            flush_json(data)
            if cli_args.outfile and resp.status_code == 200:
                key_path = os.path.join(storage, cli_args.outfile)
                with open(key_path, "w") as f:
                    jwk = data["jwk"]
                    json.dump(jwk, f, indent=4)
                print(f"[+] Key saved at {key_path}")
        case "did":
            method = cli_args.method
            endpoint = "create-did/"
            options = {"method": method}
            key_path = os.path.join(storage, cli_args.key_file)
            options["publicJwk"] = get_public_jwk(key_path)
            resp = requests.get(create_url(service_address, endpoint),
                                json=options)
            data = resp.json()
            flush_json(data)
            if cli_args.outfile and resp.status_code == 200:
                did_path = os.path.join(storage, cli_args.outfile)
                with open(did_path, "w") as f:
                    did = data["did"]
                    f.write(did)
                print(f"[+] DID saved at {did_path}")


def main_issue():
    subcommand = cli_args.issue_subcommand

    match subcommand:
        case "vc":
            issuer = cli_args.issuer
            kid = cli_args.kid
            subject = cli_args.subject
            key_path = os.path.join(storage, cli_args.key_file)
            with open(key_path, "r") as f:
                jwk = json.load(f)
            endpoint = "issue-credential/"
            resp = requests.get(create_url(service_address, endpoint), json={
                "issuer": issuer,
                "subject": subject,
                "jwk": jwk,
                "kid": kid,
            })
            data = resp.json()
            flush_json(data)
            if cli_args.outfile and resp.status_code == 200:
                vc_path = os.path.join(storage, cli_args.outfile)
                with open(vc_path, "w") as f:
                    token = data["vcJwt"]
                    f.write(token)
                print(f"[+] VC token saved at {vc_path}")
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
    create_key.add_argument("--alg", type=str, metavar="ALGORITHM",
                        choices=["rsa", "secp256k1"],
                        default="secp256k1", help="Underlying cryptosystem")
    create_key.add_argument("--out", type=str, metavar="OUTFILE",
                        dest="outfile",
                        help="Save key inside .storage")

    ### create did
    create_did = create_subcommand.add_parser("did",
                        help="Create DID")
    create_did.add_argument("--key", type=str, metavar="FILE",
                        required=True, dest="key_file",
                        help="Key to use from .storage")
    create_did.add_argument("--method", type=str, metavar="METHOD",
                        choices=["key", "ebsi"],
                        default="ebsi", help="DID method")
    create_did.add_argument("--out", type=str, metavar="OUTFILE",
                        dest="outfile",
                        help="Save DID inside .storage")

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
                        dest="key_file", required=True,
                        help="Issuer's private JWK")
    issue_vc.add_argument("--kid", type=str, metavar="<KID>",
                        default="CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc",
                        help="Issuer's JWK kid")
    issue_vc.add_argument("--subject", type=str, metavar="<DID>",
                        default="did:ebsi:z25a23eWUxQQzmAgnD9srpMM",
                        help="Subject DID")
    issue_vc.add_argument("--out", type=str, metavar="OUTFILE",
                        dest="outfile",
                        help="Save VC inside .storage")

    ### issue vp
    issue_vp = issue_subcommand.add_parser("vp",
                        help="Issue verifiable presentation")
    # TODO: Options


    global cli_args
    global service_address
    global storage
    cli_args = parser.parse_args()
    service_address = f"http://{cli_args.host}:{cli_args.port}"
    storage =  ".storage"  # TODO: Consider parametrizing this

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
