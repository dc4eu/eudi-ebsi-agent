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
POST /create-key

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
POST /create-did

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
POST /resolve-did

{
    "did": ...
}
```

**200**

```
{
    "didDocument": {
        ...
    }
}
```

### VC issuance

```
POST /issue-vc

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
    },
    "claims": {
        ...
    }
}
```

**200**
```
{
    "token": ...
}
```

### VC verification

```
POST /verify-vc

{
    "token": ...
}
```

**200**

```
{
    "vcDocument": {
        ...
    }
}
```

**400**

```
{
    "error": {
        "message": ...,
        "name": ...
    }
}
```

### VP issuance

```
POST /issue-vp

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

**200**
```
{
    "token": ...
}
```

### VP verification

```
POST /verify-vp

{
    "token": ...
    "audience": {
        "did": ...
    }
}
```

**200**

```
{
    "vpDocument": {
        ...
    }
}
```

**400**

```
{
    "error": {
        "message": ...,
        "name": ...
    }
}
```

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
    --claims-json ".storage/claims-sample.json" \
    --claims "gender=unspecified" \
    --out vc-1.jwt
```

#### VC verification

```shell
python api-client.py verify vc vc-sample.jwt --out vc-sample.json
```

#### VP issuance

```shell
python3 api-client.py issue vp \
    --key signer.jwk  \
    --kid bar \
    --signer $(cat .storage/signer.did) \
    --holder $(cat .storage/holder.did) \
    --audience $(cat .storage/audience.did) \
    --credentials vc-1.jwt vc-2.jwt \
    --out vp.jwt
```

#### VP verification

```shell
python3 api-client.py verify vp vp-sample.jwt --out vp-sample.json
```

## Development

### Tests

```shell
npm run test[:reload]
```
