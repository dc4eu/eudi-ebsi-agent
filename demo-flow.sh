#!/bin/bash
#
# The secret keys .vauly/grnet-*.jwk corresponding to the below used DIDs are
# privately owned by GRNET; contact someone in order to be able to run this
# demo locally.

set -e

source .env/bin/activate

QUIET=""
if [[ $1 == "quiet" ]]; then
    QUIET="--quiet"
fi

# The following DIDs have been registered (`onboarded`) algong with their
# respective KIDs to the EBSI registry and can be properly resolved. The
# respective secret keys are private owned by GRNET for demo purposes. The
# isuer DID is further registered as a Trusted Issuer (TI)

ISSUER_DID="did:ebsi:zwLFeK372v5tLJbU6U5xPoX"
ISSUER_KID="lmvb8kK8r_Vu0FKVjyoirL5DC_7hVoTfI7wfxpkSUQY"

HOLDER_DID="did:ebsi:z23wc4CgC8oMXfDggCSz4C6B"
HOLDER_KID="lk4lfYkT9imHJKH-cCqpX_qf6FZiP5RT48uuPfJLU9Y"

VERIFIER_DID="did:ebsi:z24acuDqgwY9qHjzEQ1r6YvF"
VERIFIER_KID="0jQcL804FqHARBeiHzuok5sWChT1rfaqg9P0rjC2ZZU"

# Issue 1st credential (VC)
python3 api-client.py ${QUIET} issue vc \
    --key grnet-issuer.jwk  \
    --kid ${ISSUER_KID} \
    --issuer ${ISSUER_DID} \
    --subject ${HOLDER_DID} \
    --claims-json ".storage/claims-sample.json" \
    --claims "gender=unspecified" \
    --out demo-vc-1.jwt

# Issue 2nd credential (VC)
python3 api-client.py ${QUIET} issue vc \
    --key grnet-issuer.jwk  \
    --kid ${ISSUER_KID} \
    --issuer ${ISSUER_DID} \
    --subject ${HOLDER_DID} \
    --claims-json ".storage/claims-sample.json" \
    --claims "placeOfBirth=Khartoum" \
    --out demo-vc-2.jwt

# Verify credentials separately and save the recovered documents
python3 api-client.py ${QUIET} verify vc demo-vc-1.jwt --out demo-vc-1.json
python3 api-client.py ${QUIET} verify vc demo-vc-2.jwt --out demo-vc-2.json

# Create verifiable presentation (VP) containing the above credentials
python3 api-client.py ${QUIET} issue vp \
    --key grnet-holder.jwk  \
    --kid ${HOLDER_KID} \
    --signer ${HOLDER_DID} \
    --holder ${HOLDER_DID} \
    --audience ${VERIFIER_DID} \
    --credentials demo-vc-1.jwt demo-vc-2.jwt \
    --out demo-vp.jwt

# Verify presentation and save the recovered document
python3 api-client.py ${QUIET} verify vp demo-vp.jwt \
    --audience ${VERIFIER_DID} \
    --out demo-vp.json
