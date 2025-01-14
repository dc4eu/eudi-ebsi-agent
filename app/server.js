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

import { issueCredential } from "./vc.js";
import { resolveAlgorithm } from "./util.js";


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

  let key;
  try {
    key = await generateJwkPair(crypto);
  } catch(err) {
    return res.status(400).json({ error: err.message });
  }

  res.json({ key })
});



app.get("/create-did", async (req, res) => {
  const body = req.body;
  if (!body) {
    return res.status(400).json({ error: "Malformed request: No body" });
  }
  const { method, publicJwk } = req.body;

  if (!method) {
    return res.status(400).json({ error: "Malformed request: No method specified" });
  }
  if (!publicJwk) {
    return res.status(400).json({ error: "Malformed request: No JWK specified" });
  }

  let did;
  try {
    did = await createDidFromJwk(method, publicJwk);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  res.json({ did });
});


app.get("/issue-credential", async (req, res) => {
  const body = req.body;
  if (!body) {
    return res.status(400).json({ error: "Malformed request: No body" });
  }
  const {
    issuer: issuer_did, subject: subject_did, jwk: issuer_jwk, kid: issuer_kid,
  } = req.body;

  if (!issuer_did) {
    return res.status(400).json({ error: "Malformed request: No issuer DID specified" });
  }

  if (!issuer_jwk) {
    return res.status(400).json({ error: "Malformed request: No issuer JWK specified" });
  }

  if (!issuer_kid) {
    return res.status(400).json({ error: "Malformed request: No issuer kid specified" });
  }

  if (!subject_did) {
    return res.status(400).json({ error: "Malformed request: No subject DID specified" });
  }

  if (resolveAlgorithm(issuer_jwk) != "ES256K") {
    return res.status(400).json({ error: "Only secp256k1 keys are allowed to issue!" });
  }

  const vcJwt = await issueCredential(issuer_jwk, issuer_did, issuer_kid, subject_did);
  res.json({ vcJwt });
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
