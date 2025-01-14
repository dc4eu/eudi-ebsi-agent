#!/bin/bash

source .env/bin/activate

# Setup issuer identity
python api-client.py create key --alg secp256k1 --out issuer.jwk
python api-client.py create did --key issuer.jwk --method ebsi --out issuer.did

# Setup holder identity
python api-client.py create key --alg secp256k1 --out holder.jwk
python api-client.py create did --key holder.jwk --method ebsi --out holder.did

# Issue credential
python api-client.py issue vc \
    --key issuer.jwk  \
    --kid foo \
    --issuer $(cat .storage/issuer.did) \
    --subject $(cat .storage/holder.did)

# python api-client.py resolve did:ebsi:ziDnioxYYLW1a3qUbqTFz4W
