#!/bin/bash
#
# The private keys ./vaut/grnet-*.jwk corresponding to the DIDs used below are
# owned by GRNET; contact fmerg@grnet.gr to get them and be able to run this
# demo locally

source .env/bin/activate

# Issue 1st credential
python3 api-client.py issue vc \
    --key grnet-issuer.jwk  \
    --kid lmvb8kK8r_Vu0FKVjyoirL5DC_7hVoTfI7wfxpkSUQY \
    --issuer $(<.storage/grnet-issuer.did) \
    --subject $(<.storage/grnet-holder.did) \
    --claims-json ".storage/claims-sample.json" \
    --claims "gender=unspecified" \
    --out demo-vc-1.jwt

# Issue 2nd credential
python3 api-client.py issue vc \
    --key grnet-issuer.jwk  \
    --kid lmvb8kK8r_Vu0FKVjyoirL5DC_7hVoTfI7wfxpkSUQY \
    --issuer $(<.storage/grnet-issuer.did) \
    --subject $(<.storage/grnet-holder.did) \
    --claims-json ".storage/claims-sample.json" \
    --claims "placeOfBirth=Khartoum" \
    --out demo-vc-2.jwt

# Verify credentials separately
python3 api-client.py verify vc demo-vc-1.jwt --out demo-vc-1.json
python3 api-client.py verify vc demo-vc-2.jwt --out demo-vc-2.json

# Create verifiable presentation containing the above credentials
python3 api-client.py issue vp \
    --key grnet-holder.jwk  \
    --kid lk4lfYkT9imHJKH-cCqpX_qf6FZiP5RT48uuPfJLU9Y \
    --signer $(<.storage/grnet-holder.did) \
    --holder $(<.storage/grnet-holder.did) \
    --audience $(<.storage/grnet-audience.did) \
    --credentials demo-vc-1.jwt demo-vc-2.jwt \
    --out demo-vp.jwt

# Verify presentation
python3 api-client.py verify vp demo-vp.jwt \
    --audience $(<.storage/grnet-audience.did) \
