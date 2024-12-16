#!/bin/bash

source .env/bin/activate

python api-client.py create key --crypto secp256k1 --out key.json
python api-client.py create did --key key.json --method ebsi --out did.json
python api-client.py resolve did:ebsi:ziDnioxYYLW1a3qUbqTFz4W
