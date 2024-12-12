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

### Identity creation

```
GET /create-did

{
  "jwk": <JWK>,
  "crypto": <SYSTEM>,
  "method": <METHOD>,
}
```

```
{
  "did": <DID>,
  "privateJwk": {
    ...
  },
  "publicJwk": {
    ...
  }
}
```

### DID resolution

```
GET /resolve

{
  "did": <DID>
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

### Examples

```shell
python api-client.py fetch info
```

```shell
python api-client.py resolve did:ebsi:zvHWX359A3CvfJnCYaAiAde
```

## Development

### Tests

```shell
npm run test[:reload]
```
