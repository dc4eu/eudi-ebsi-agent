#!/bin/bash

# CRYPTOGRAPHIC CONFIGURATION +++++++++++++++++++++++++++++++++++++++++++++++

# The secret keys .vault/grnet-*.jwk corresponding to the below used DIDs are
# privately owned by GRNET; contact someone in order to be able to run this
# demo locally.

# The following DIDs have been registered (`onboarded`) along with their
# respective KIDs to the EBSI registry and can be properly resolved. The
# respective secret keys are private owned by GRNET for demo purposes. The
# isuer DID is further registered as a Trusted Issuer (TI)

ISSUER_DID="did:ebsi:zwLFeK372v5tLJbU6U5xPoX"
ISSUER_KID="lmvb8kK8r_Vu0FKVjyoirL5DC_7hVoTfI7wfxpkSUQY"

HOLDER_DID="did:ebsi:z23wc4CgC8oMXfDggCSz4C6B"
HOLDER_KID="lk4lfYkT9imHJKH-cCqpX_qf6FZiP5RT48uuPfJLU9Y"

VERIFIER_DID="did:ebsi:z24acuDqgwY9qHjzEQ1r6YvF"
VERIFIER_KID="0jQcL804FqHARBeiHzuok5sWChT1rfaqg9P0rjC2ZZU"


# CLIENT CONFIGURATION ++++++++++++++++++++++++++++++++++++++++++++++++++++++

DEFAULT_PROTOCOL="http"
DEFAULT_HOST="localhost"
DEFAULT_PORT="3000"
DEFAULT_INSTALL="false"
DEFAULT_NO_RUN="false"

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


usage_string="usage: ./$(basename "$0") [OPTIONS]

Usage
-----

Create virtual environment \`./.env\` and install requirements without running the demo:

  $ ./$(basename "$0") --install --no-run

Run demo with default client, connecting to http://localhost:3000:

  $ ./$(basename "$0")

Run demo with explicit client configuration:

  $ ./$(basename "$0") --protocol https --host snf-36159.ok-kno.grnetcloud.net/ebsi-agent


Options
-------

  --protocol [http|https]   Transfer protocol (default: http)
  --host HOST               Service domain name (default: localhost)
  --port PORT               Listening port. Useful when combined with localhost (default: 3000)
  -i, --install             Create virtual environment \`./.env\` and install requirements
                            Deletes any existing installation
  -n, --no-run              Do not run demo. Useful when combined with --install
  -h, --help                Display help message and exit

"

usage() { echo -n "$usage_string" 1>&2; }


install_requirements() {
    source .env/bin/activate
    python3 -m ensurepip --upgrade
    python3 -m pip install --upgrade pip
    pip install -r requirements-client.txt
    deactivate
}

set -e

PROTOCOL="${DEFAULT_PROTOCOL}"
HOST="${DEFAULT_HOST}"
PORT="${DEFAULT_PORT}"
INSTALL="${DEFAULT_INSTALL}"
NO_RUN="${DEFAULT_NO_RUN}"


while [[ $# -gt 0 ]]
do
    arg="$1"
    case $arg in
        --protocol)
            PROTOCOL="$2"
            shift
            shift
            ;;
        --host)
            HOST="$2"
            shift
            shift
            ;;
        --port)
            PORT="$2"
            shift
            shift
            ;;
        -i|--install)
            INSTALL="true"
            shift
            ;;
        -n|--no-run)
            NO_RUN="true"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[-] Invalid argument: $arg"
            usage
            exit 1
            ;;
    esac
done


if [[ ${INSTALL} == true ]]; then
    rm -rf .env && python3 -m venv .env && install_requirements
fi

if [[ ${NO_RUN} == true ]]; then
    exit 0
fi


source .env/bin/activate

CLIENT_CONFIG="--protocol ${PROTOCOL} --host ${HOST}"
if [ -n "${PORT}" ]; then
    CLIENT_CONFIG+=" --port $PORT"
fi


# Issue 1st credential (VC)
python3 api-client.py ${CLIENT_CONFIG} issue vc \
    --key grnet-issuer.jwk  \
    --kid ${ISSUER_KID} \
    --issuer ${ISSUER_DID} \
    --subject ${HOLDER_DID} \
    --claims-json ".storage/claims-sample.json" \
    --claims "gender=unspecified" \
    --out demo-vc-1.jwt

# Issue 2nd credential (VC)
python3 api-client.py ${CLIENT_CONFIG} issue vc \
    --key grnet-issuer.jwk  \
    --kid ${ISSUER_KID} \
    --issuer ${ISSUER_DID} \
    --subject ${HOLDER_DID} \
    --claims-json ".storage/claims-sample.json" \
    --claims "placeOfBirth=Khartoum" \
    --out demo-vc-2.jwt

# Verify credentials separately and save the recovered documents
python3 api-client.py ${CLIENT_CONFIG} verify vc demo-vc-1.jwt --out demo-vc-1.json
python3 api-client.py ${CLIENT_CONFIG} verify vc demo-vc-2.jwt --out demo-vc-2.json

# Create verifiable presentation (VP) containing the above credentials
python3 api-client.py ${CLIENT_CONFIG} issue vp \
    --key grnet-holder.jwk  \
    --kid ${HOLDER_KID} \
    --signer ${HOLDER_DID} \
    --holder ${HOLDER_DID} \
    --audience ${VERIFIER_DID} \
    --credentials demo-vc-1.jwt demo-vc-2.jwt \
    --out demo-vp.jwt

# Verify presentation and save the recovered document
python3 api-client.py ${CLIENT_CONFIG} verify vp demo-vp.jwt \
    --audience ${VERIFIER_DID} \
    --out demo-vp.json
