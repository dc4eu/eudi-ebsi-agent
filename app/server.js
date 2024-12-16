import express from "express";
import path from "path";

import { Resolver } from "did-resolver";
import { getResolver } from "@cef-ebsi/ebsi-did-resolver";

import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { calculateJwkThumbprint, exportJWK, generateKeyPair } from "jose";

import { util as utilEbsi } from "@cef-ebsi/ebsi-did-resolver";

import { randomBytes } from "node:crypto";

const registry = "https://api-pilot.ebsi.eu/did-registry/v5/identifiers";

const resolverConfig = { registry };
const ebsiResolver = getResolver(resolverConfig);
const didResolver = new Resolver(ebsiResolver);

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));


app.get("/", (req, res) => {
  res.send("Service is up")
});

async function generateJwkPair(crypto) {
  const cryptoMapping = {
    "ES256K": "ES256K",
    "secp256k1": "ES256K",
    "PS256": "PS256",
    "rsa": "PS256",
    "RSA": "PS256",
  }
  const label = cryptoMapping[crypto];
  if (!label) {
      throw Error(`Unsupported crypto: ${crypto}`);
  }
  const { privateKey, publicKey } = await generateKeyPair(label);

  const privateJwk = await exportJWK(privateKey);
  const publicJwk = await exportJWK(publicKey);
  return { privateJwk, publicJwk };
}


async function createDidFromJwk(method, publicJwk) {
  const methodMapping = {
    "key": "NATURAL_PERSON",
    "ebsi": "LEGAL_ENTITY",
  };

  const label = methodMapping[method];
  if (!label) {
      throw Error(`Unsupported method: ${method}`);
  }
  const did = EbsiWallet.createDid(label, publicJwk);

  return did;
}


app.get("/info", async (req, res) => {
  res.json({
    "name": "EBSI Ledger Onboarding Service",
  });
});


app.get("/create-key", async (req, res) => {
  const body = req.body;
  if (!body) {
    return res.status(400).json({ error: "Malformed request: No body" });
  }
  const { crypto } = req.body;
  if (!crypto) {
    return res.status(400).json({ error: "Malformed request: No crypto specified" });
  }

  let keypair;
  try {
    keypair = await generateJwkPair(crypto);
  } catch(err) {
    return res.status(400).json({ error: err.message });
  }
  const { privateJwk, publicJwk } = keypair;

  res.json({ privateJwk, publicJwk });
});



app.get("/create-did", async (req, res) => {
  const body = req.body;
  if (!body) {
    return res.status(400).json({ error: "Malformed request: No body" });
  }
  const { crypto, jwk, method } = req.body;

  if (!method) {
    return res.status(400).json({ error: "Malformed request: No method specified" });
  }
  if (!jwk && !crypto) {
    return res.status(400).json({ error: "Malformed request: No crypto specified" });
  }

  let privateJwk, publicJwk;
  if (!jwk) {
    let keypair;
    try {
      keypair = await generateJwkPair(crypto);
    } catch(err) {
      return res.status(400).json({ error: err.message });
    }
    privateJwk = keypair.privateJwk;
    publicJwk = keypair.publicJwk;
  } else {
    publicJwk = jwk;
  }

  let did;
  try {
    did = await createDidFromJwk(method, publicJwk);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  res.json({ did, privateJwk, publicJwk });
});


app.get("/resolve-did", async (req, res) => {
  const body = req.body;
  if (!body) {
    return res.status(400).json({ error: "Malformed request: No body" });
  }
  const { did } = body;
  if (!did) {
    return res.status(400).json({ error: "Malformed request: No did specified" });
  }

  const result = await didResolver.resolve(body.did);
  if (!result.didDocument) {
    const error = result.didResolutionMetadata.error;
    switch (error) {
      case "notFound":
        return res.status(400).json({ error: "DID not found" });
      case "invalidDid":
        return res.status(400).json({ error: "Invalid DID" });
      default:
        return res.status(400).json({ error });
    }
  }

  res.json(result);
});


const hostname = "0.0.0.0";
const port = process.env.PORT || 1337;
app.listen(port, hostname, () => {
  console.log(`Server listening at port: ${port}`)
})


export default app;
