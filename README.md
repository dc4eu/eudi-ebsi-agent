# EBSI Agent Service

## Spin up service

```shell
docker compose up [--build]
```

Visit [`localhost:3000`](http://localhost:3000)

## Endpoints

### Service info

```
GET /info
```

### Key creation

```
GET /create-key

{
  "alg": "rsa" | "secp256k1"
}
```

```
{
  "jwk": {
    ...
  }
}
```

### DID creation

```
GET /create-did

{
  "method": "key" | "ebsi",
  "publicJwk": {
    ...
  }
}
```

```
{
  "did": <DID>,
}
```

### DID resolution

```
GET /resolve-did

{
  "did": ...
}
```

```
{
  "didDocument": {
    ...
  }
}
```

### VC issuance

```
GET /issue-vc

{
  "issuer": {
    "did": ...,
    "kid": ...,
    "jwk": {
      ...
    }
  },
  "subject": {
    "did": ...
  }
}
```

```
{
  "token": ...
}
```

### VC verification

```
GET /verify-vc

{
  "token": ...
}
```

```
{
  "result": {
    ...
  }
}
```

### VP issuance

```
GET /issue-vp

{
  "signer": {
    "did": ...,
    "kid": ...,
    "jwk": {
      ...
    }
  },
  "holder": {
    "did": ...
  },
  "audience": {
    "did": ...
  },
  credentials: [
    ...
  ]
}
```

```
{
  "token": ...
}
```

### VP verification

TODO

## Reference API Client

### Setup

```shell
python -m venv .env
```

```shell
source .env/bin/activate
pip install -r requirements-client.txt
```

### Usage

Assuming that the virtual environment is activated:

```shell
python api-client.py --help
```

#### Service info

```shell
python api-client.py fetch info
```

#### Key creation

```shell
python api-client.py create key --alg secp256k1 --out issuer.jwk
```

#### DID creation

```shell
python api-client.py create did --key issuer.jwk --method ebsi --out issuer.did
```

#### DID resolution

```shell
python api-client.py resolve did:ebsi:ziDnioxYYLW1a3qUbqTFz4W
```

#### VC issuance

```shell
python api-client.py issue vc \
    --key issuer.jwk  \
    --kid foo \
    --issuer $(cat .storage/issuer.did) \
    --subject $(cat .storage/holder.did) \
    --out vc-1.jwt
```

#### VC verification

```shell
python api-client.py verify vc vc-sample.jwt
```

#### VP issuance

TODO

#### VP verification

TODO

## Development

### Tests

```shell
npm run test[:reload]
```
