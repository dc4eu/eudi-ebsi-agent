# EBSI Ledger Onboarding Service

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
  "crypto": "rsa" | "RSA" | "secp256k1" | "ES256K",
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
  "didDocument": {
    ...
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
python api-client.py create key --crypto secp256k1 [--out key.json]
```

#### DID creation

```shell
python api-client.py create did --key key.json --method ebsi [--out did.json]
```

#### DID resolution

```shell
python api-client.py resolve did:ebsi:ziDnioxYYLW1a3qUbqTFz4W
```

## Development

### Tests

```shell
npm run test[:reload]
```
