# EBSI Ledger Onboarding Service

## Spin up service

```shell
docker compose up [--build]
```

Visit [`localhost:3000`](http://localhost:3000)

## Endpoints

```
GET /info
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

## Development

### Tests

```shell
npm run dev
```
