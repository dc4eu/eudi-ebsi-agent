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

STORAGE =  ".storage"   # Storage for DIDs, tokens and documents
VAULT   =  ".vault"     # Key storage

SERVICE_ADDRESS = None
cli_args = None

def print_ok(message):
    print("\033[92m" +  f"[+] {message}" + "\033[0m")

def print_fail(message):
    print("\033[91m" +  f"[-] {message}" + "\033[0m")

def create_address(cli_args):
    address = f"{cli_args.protocol}://{cli_args.host}"
    if cli_args.host == "localhost":
        address += f":{cli_args.port}"
    else:
        if not address.endswith("/"):
            address += "/"
    return address

def create_url(address, endpoint):
    return urljoin(address, endpoint.lstrip("/"))

def flush_json(payload, indent=4, nojump=False):
    if not cli_args.quiet:
        print(json.dumps(payload, indent=indent))

def load_public_jwk(key_path):
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


def main_fetch():
    subcommand = cli_args.fetch_subcommand

    match subcommand:
        case "info":
            endpoint = "info/"
            resp = requests.get(create_url(SERVICE_ADDRESS,
                                           endpoint))
            data = resp.json()
            flush_json(data)
        case _:
            print("No action specified")
            sys.exit(1)


def main_resolve():
    did = cli_args.did
    endpoint = "resolve-did/"
    resp = requests.post(create_url(SERVICE_ADDRESS, endpoint), json={
        "did": did
    })
    data = resp.json()
    flush_json(data)


def main_create():
    subcommand = cli_args.create_subcommand

    match subcommand:
        case "key":
            endpoint = "create-key/"
            resp = requests.post(create_url(SERVICE_ADDRESS, endpoint), json={
                "alg": cli_args.alg,
            })
            data = resp.json()
            flush_json(data)
            if resp.status_code != 200:
                print_fail("Could not generate key")
                sys.exit(1)
            if cli_args.outfile:
                key_path = os.path.join(VAULT, cli_args.outfile)
                with open(key_path, "w") as f:
                    jwk = data["jwk"]
                    json.dump(jwk, f, indent=4)
                print_ok(f"Key saved at {key_path}")
        case "did":
            method = cli_args.method
            endpoint = "create-did/"
            options = {"method": method}
            key_path = os.path.join(VAULT, cli_args.key_file)
            options["publicJwk"] = load_public_jwk(key_path)
            resp = requests.post(create_url(SERVICE_ADDRESS, endpoint),
                                json=options)
            data = resp.json()
            flush_json(data)
            if resp.status_code != 200:
                print_fail("Could not create DID")
                sys.exit(1)
            if cli_args.outfile:
                did_path = os.path.join(STORAGE, cli_args.outfile)
                with open(did_path, "w") as f:
                    did = data["did"]
                    f.write(did)
                print_ok(f"DID saved at {did_path}")
        case _:
            print("No action specified")
            sys.exit(1)


def main_issue():
    subcommand = cli_args.issue_subcommand

    match subcommand:
        case "vc":
            key_path = os.path.join(VAULT, cli_args.key_file)
            with open(key_path, "r") as f:
                jwk = json.load(f)

            claims = {}
            # Parse JSON formatted claims
            if cli_args.claims_json:
                with open(cli_args.claims_json, "r") as f:
                    claims = json.load(f)
            # Parse individual claims (assumes string key-value pairs)
            if cli_args.claims:
                for pair in cli_args.claims:
                    key, value = pair.split("=")
                    claims[key] = value

            endpoint = "issue-vc/"
            resp = requests.post(create_url(SERVICE_ADDRESS, endpoint), json={
                "issuer": {
                    "did": cli_args.issuer,
                    "jwk": jwk,
                    "kid": cli_args.kid,
                },
                "subject": {
                    "did": cli_args.subject
                },
                "claims": claims,
            })
            data = resp.json()
            flush_json(data)
            if resp.status_code != 200:
                print_fail("Could not issue VC")
                sys.exit(1)
            if cli_args.outfile:
                vc_path = os.path.join(STORAGE, cli_args.outfile)
                with open(vc_path, "w") as f:
                    token = data["token"]
                    f.write(token)
                print_ok(f"VC token saved at {vc_path}")
        case "vp":
            key_path = os.path.join(VAULT, cli_args.key_file)
            with open(key_path, "r") as f:
                jwk = json.load(f)

            # Load VC tokens
            vc_tokens = []
            for vc_file in cli_args.credentials:
                vc_path = os.path.join(STORAGE, vc_file)
                with open(vc_path, "r") as f:
                    vc_token = f.read().rstrip()
                vc_tokens += [vc_token]

            endpoint = "issue-vp/"
            resp = requests.post(create_url(SERVICE_ADDRESS, endpoint), json={
                "signer": {
                    "did": cli_args.signer,
                    "jwk": jwk,
                    "kid": cli_args.kid,
                },
                "holder": {
                    "did": cli_args.holder
                },
                "audience": {
                    "did": cli_args.audience
                },
                "credentials": vc_tokens,
            })
            data = resp.json()
            flush_json(data)
            if resp.status_code != 200:
                print_fail("Could not issue VP")
                sys.exit(1)
            if cli_args.outfile:
                vp_path = os.path.join(STORAGE, cli_args.outfile)
                with open(vp_path, "w") as f:
                    token = data["token"]
                    f.write(token)
                print_ok(f"VP token saved at {vp_path}")
        case _:
            print("No action specified")
            sys.exit(1)


def main_verify():
    subcommand = cli_args.verify_subcommand

    match subcommand:
        case "vc":
            vc_path = os.path.join(STORAGE, cli_args.vc_file)
            with open(vc_path, "r") as f:
                token = f.read().rstrip()
            endpoint = "verify-vc/"
            resp = requests.post(create_url(SERVICE_ADDRESS, endpoint), json={
                "token": token
            })
            data = resp.json()
            flush_json(data)
            if resp.status_code != 200:
                print_fail("Could not verify VC token")
                sys.exit(1)
            if cli_args.outfile:
                vc_path = os.path.join(STORAGE, cli_args.outfile)
                with open(vc_path, "w") as f:
                    vc_doc = data["vcDocument"]
                    json.dump(vc_doc, f, indent=4)
                print_ok(f"VC document saved at {vc_path}")
        case "vp":
            vp_path = os.path.join(STORAGE, cli_args.vp_file)
            with open(vp_path, "r") as f:
                token = f.read().rstrip()
            endpoint = "verify-vp/"
            resp = requests.post(create_url(SERVICE_ADDRESS, endpoint), json={
                "token": token,
                "audience": {
                    "did": cli_args.audience
                }
            })
            data = resp.json()
            flush_json(data)
            if resp.status_code != 200:
                print_fail("Could not verify VP token")
                sys.exit(1)
            if cli_args.outfile:
                vp_path = os.path.join(STORAGE, cli_args.outfile)
                with open(vp_path, "w") as f:
                    vp_doc = data["vpDocument"]
                    json.dump(vp_doc, f, indent=4)
                print_ok(f"VP document saved at {vp_path}")
        case _:
            print("No action specified")
            sys.exit(1)


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
    parser.add_argument("--protocol", type=str, default="http",
                        choices=["http", "https"],
                        help="Transfer protocol")
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
                        help="Save key inside .vault")

    ### create did
    create_did = create_subcommand.add_parser("did",
                        help="Create DID")
    create_did.add_argument("--key", type=str, metavar="FILE",
                        required=True, dest="key_file",
                        help="Key to use from .vault")
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
    issue_vc.add_argument("--key", type=str, metavar="<FILE>",
                        dest="key_file", required=True,
                        help="Issuer's private JWK")
    issue_vc.add_argument("--kid", type=str, metavar="<KID>",
                        required=True,
                        help="Issuer's JWK kid")
    issue_vc.add_argument("--issuer", type=str, metavar="<DID>",
                        required=True,
                        help="Issuer DID")
    issue_vc.add_argument("--subject", type=str, metavar="<DID>",
                        required=True,
                        help="Subject DID")
    issue_vc.add_argument("--claims-json", type=str, metavar="<FILE>",
                        help="Pass claims in JSON format")
    issue_vc.add_argument("--claims", nargs="*", metavar="key_1=val_1 key_2=val_2",
                        help="Pass claims mannualy (keys and values handled as strings)")
    issue_vc.add_argument("--out", type=str, metavar="OUTFILE",
                        dest="outfile",
                        help="Save VC inside .storage")

    ### issue vp
    issue_vp = issue_subcommand.add_parser("vp",
                        help="Issue verifiable presentation")
    issue_vp.add_argument("--key", type=str, metavar="<FILE>",
                        dest="key_file", required=True,
                        help="Signer's private JWK")
    issue_vp.add_argument("--kid", type=str, metavar="<KID>",
                        required=True,
                        help="Signer's JWK kid")
    issue_vp.add_argument("--signer", type=str, metavar="<DID>",
                        required=True,
                        help="Signer DID")
    issue_vp.add_argument("--holder", type=str, metavar="<DID>",
                        required=True,
                        help="Holder DID")
    issue_vp.add_argument("--audience", type=str, metavar="<DID>",
                        required=True,
                        help="Audience DID")
    issue_vp.add_argument("--credentials", nargs="+", metavar="<FILES>",
                        required=True,
                        help="VC token files")
    issue_vp.add_argument("--out", type=str, metavar="OUTFILE",
                        dest="outfile",
                        help="Save VP inside .storage")

    # verify
    verify = commands.add_parser("verify", help="Verification actions")
    verify_subcommand = verify.add_subparsers(dest="verify_subcommand")

    ## verify vc
    verify_vc = verify_subcommand.add_parser("vc",
                        help="verify credential")
    verify_vc.add_argument("vc_file", type=str, metavar="<FILE>",
                         help="VC JWT to verify (must be in .storage)")
    verify_vc.add_argument("--out", type=str, metavar="OUTFILE",
                        dest="outfile",
                        help="Save retrieved VC inside .storage")

    ## verify vp
    verify_vp = verify_subcommand.add_parser("vp",
                        help="verify presentation")
    verify_vp.add_argument("vp_file", type=str, metavar="<FILE>",
                         help="VP JWT to verify (must be in .storage)")
    verify_vp.add_argument("--audience", type=str, metavar="<DID>",
                        required=True,
                        help="Audience DID")
    verify_vp.add_argument("--out", type=str, metavar="OUTFILE",
                        dest="outfile",
                        help="Save retrieved VP inside .storage")


    global SERVICE_ADDRESS, cli_args
    cli_args = parser.parse_args()
    SERVICE_ADDRESS = create_address(cli_args)

    match cli_args.command:
        case "fetch":
            main_fetch()
        case "create":
            main_create()
        case "resolve":
            main_resolve()
        case "issue":
            # Preliminary check for VC issuance (claims are obligatory)
            if cli_args.issue_subcommand == "vc" and not (
                cli_args.claims_json or cli_args.claims
            ):
                parser.error(
                    "At least one of --claims-json or --claims is required"
                )
            main_issue()
        case "verify":
            main_verify()



if __name__ == "__main__":
    main()
