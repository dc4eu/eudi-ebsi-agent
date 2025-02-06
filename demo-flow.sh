#!/bin/bash

source .env/bin/activate

# Setup issuer identity
python3 api-client.py create key --alg secp256k1 --out demo-issuer.jwk
python3 api-client.py create did --key demo-issuer.jwk --method ebsi --out demo-issuer.did

# Setup signer identity (normally the same as holder)
python3 api-client.py create key --alg secp256k1 --out demo-signer.jwk
python3 api-client.py create did --key demo-signer.jwk --method ebsi --out demo-signer.did

# Setup holder identity
python3 api-client.py create key --alg secp256k1 --out demo-holder.jwk
python3 api-client.py create did --key demo-holder.jwk --method ebsi --out demo-holder.did

# Setup audience identity
python3 api-client.py create key --alg secp256k1 --out demo-audience.jwk
python3 api-client.py create did --key demo-audience.jwk --method ebsi --out demo-audience.did

# Issue 1st credential
python3 api-client.py issue vc \
    --key demo-issuer.jwk  \
    --kid demo-foo \
    --issuer $(cat .storage/demo-issuer.did) \
    --subject $(cat .storage/demo-holder.did) \
    --claims-json ".storage/claims-sample.json" \
    --claims "gender=unspecified" \
    --out demo-vc-1.jwt

# Issue 2nd credential
python3 api-client.py issue vc \
    --key demo-issuer.jwk  \
    --kid demo-foo \
    --issuer $(cat .storage/demo-issuer.did) \
    --subject $(cat .storage/demo-holder.did) \
    --claims-json ".storage/claims-sample.json" \
    --claims "placeOfBirth=Khartoum" \
    --out demo-vc-2.jwt

# # Create verifiable presentation containing the above credentials
# python3 api-client.py issue vp \
#     --key demo-signer.jwk  \
#     --kid demo-bar \
#     --signer $(cat .storage/demo-signer.did) \
#     --holder $(cat .storage/demo-holder.did) \
#     --audience $(cat .storage/demo-audience.did) \
#     --credentials demo-vc-1.jwt demo-vc-2.jwt \
#     --out demo-vp.jwt

# TODO: Integrate these actions to demo flow when possible
python3 api-client.py resolve $(cat .storage/onboarded-sample.did)
python3 api-client.py verify vc vc-sample.jwt --out vc-sample.json
# python3 api-client.py verify vp vp-sample.jwt \
#     --audience "did:ebsi:zwNAE5xThBpmGJUWAY23kgx" \
#     --out vp-sample.json
