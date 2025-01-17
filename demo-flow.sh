#!/bin/bash

source .env/bin/activate

# Setup issuer identity
python3 api-client.py create key --alg secp256k1 --out issuer.jwk
python3 api-client.py create did --key issuer.jwk --method ebsi --out issuer.did

# Setup signer identity
python3 api-client.py create key --alg secp256k1 --out signer.jwk
python3 api-client.py create did --key signer.jwk --method ebsi --out signer.did

# Setup holder identity
python3 api-client.py create key --alg secp256k1 --out holder.jwk
python3 api-client.py create did --key holder.jwk --method ebsi --out holder.did

# Setup audience identity
python3 api-client.py create key --alg secp256k1 --out audience.jwk
python3 api-client.py create did --key audience.jwk --method ebsi --out audience.did

# Issue 1st credential
python3 api-client.py issue vc \
    --key issuer.jwk  \
    --kid foo \
    --issuer $(cat .storage/issuer.did) \
    --subject $(cat .storage/holder.did) \
    --out vc-1.jwt

# Issue 2nd credential
python3 api-client.py issue vc \
    --key issuer.jwk  \
    --kid foo \
    --issuer $(cat .storage/issuer.did) \
    --subject $(cat .storage/holder.did) \
    --out vc-2.jwt

# Create verifiable presentation containing the above credentials
python3 api-client.py issue vp \
    --key signer.jwk  \
    --kid bar \
    --signer $(cat .storage/signer.did) \
    --holder $(cat .storage/holder.did) \
    --audience $(cat .storage/audience.did) \
    --credentials vc-1.jwt vc-2.jwt \
    --out vp.jwt

# TODO: Integrate these action to demo flow when possible
python3 api-client.py resolve did:ebsi:ziDnioxYYLW1a3qUbqTFz4W
python3 api-client.py verify vc vc-sample.jwt
