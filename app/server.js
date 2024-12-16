import express from "express";
import path from "path";

import { Resolver } from "did-resolver";
import { getResolver } from "@cef-ebsi/ebsi-did-resolver";

import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { calculateJwkThumbprint, exportJWK, generateKeyPair } from "jose";

import { util as utilEbsi } from "@cef-ebsi/ebsi-did-resolver";

import { randomBytes } from "node:crypto";

import { createVerifiableCredentialJwt, verifyCredentialJwt } from "@cef-ebsi/verifiable-credential";

const registry = "https://api-pilot.ebsi.eu/did-registry/v5/identifiers";

const resolverConfig = { registry };
const ebsiResolver = getResolver(resolverConfig);
const didResolver = new Resolver(ebsiResolver);

const app = express();

import { ES256KSigner } from "did-jwt";


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

function base64ToBytes(base64Url) {
  // Convert to standard base64
  const normalized = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - (normalized.length % 4)) % 4);
  const base64Padded = normalized + padding;

  // Decode to binary
  return Uint8Array.from(Buffer.from(base64Padded, "base64"));
}

function resolveAlg(jwk) {
  if (!jwk || !jwk.kty) {
    throw new Error("Invalid JWK: Missing 'kty' field.");
  }

  switch (jwk.kty) {
    case "EC": // Elliptic Curve
      if (!jwk.crv) {
        throw new Error("Invalid JWK: Missing 'crv' field for EC key.");
      }
      // Resolve EC algorithms based on the curve
      switch (jwk.crv) {
        case "secp256k1":
          return "ES256K"; // ECDSA using secp256k1 and SHA-256
        case "P-256":
          return "ES256"; // ECDSA using P-256 and SHA-256
        case "P-384":
          return "ES384"; // ECDSA using P-384 and SHA-384
        case "P-521":
          return "ES512"; // ECDSA using P-521 and SHA-512
        default:
          throw new Error(`Unsupported curve: ${jwk.crv}`);
      }

    case "RSA": // RSA Keys
      if (!jwk.n || !jwk.e) {
        throw new Error("Invalid JWK: Missing 'n' or 'e' field for RSA key.");
      }
      // Typically RS256 is a default for RSA
      return "RS256";

    case "oct": // Symmetric Keys
      if (!jwk.k) {
        throw new Error("Invalid JWK: Missing 'k' field for symmetric key.");
      }
      // Example: Use HS256 for HMAC with SHA-256
      return "HS256";

    default:
      throw new Error(`Unsupported key type: ${jwk.kty}`);
  }
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
  // TODO: Parse more options here?
  const {
    issuer: issuer_did,
    subject: subject_did,
    jwk: issuer_jwk,
    kid: issuer_kid,
  } = req.body;

  const vcPayload = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    id: "urn:uuid:003a1dd8-a5d2-42ef-8182-e921c0a9f2cd",      // TODO: Properly generate
    type: ["VerifiableCredential", "VerifiableAttestation"],
    issuer: issuer_did,
    issuanceDate: "2021-11-01T00:00:00Z",   // TODO: Properly generate
    validFrom: "2021-11-01T00:00:00Z",      // TODO: Properly generate
    validUntil: "2050-11-01T00:00:00Z",     // TODO: Properly generate
    expirationDate: "2031-11-30T00:00:00Z", // TODO: Properly generate
    issued: "2021-10-30T00:00:00Z",         // TODO: Properly generate
    credentialSubject: {
      // NOTE (GRNET): Must be did:ebsi:<...>due to enabled ebsiAuthority
      id: subject_did,
    },
    credentialSchema: {
      id: "https://api-pilot.ebsi.eu/trusted-schemas-registry/v3/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM",
      type: "FullJsonSchemaValidator2021",
    },
    termsOfUse: {
      id: `https://api-pilot.ebsi.eu/trusted-issuers-registry/v5/issuers/${issuer_did}/attributes/b40fd9b404418a44d2d9911377a03130dde450eb546c755b5b80acd782902e6d`,
      type: "IssuanceCertificate",
    },
  };
  const options = {
    network: "pilot", // Required: EBSI network
    hosts: ["api-pilot.ebsi.eu"], // Required: List of trusted hosts running the EBSI Core Services APIs.
    ebsiAuthority: "api-pilot.ebsi.eu", // OPTIONAL; NOTE (GRNET): Enforces did:ebsi:<...> subject DIDs
    // OPTIONAL. Determines whether to validate the Verifiable Credential payload or not.
    // Validation is active by default.
    // NOTE: even when skipValidation is set to true, the payload must be a valid EBSI Verifiable Attestation.
    // NOTE (GRNET): We deactivate this so that we can work with non-onboarded issuer DIDs
    skipValidation: true,
    // OPTIONAL. List of trusted services with their respective version number (e.g. "v5").
    // Only declare this if you need to override the default versions.
    // services: {
    //   "did-registry": "v5",
    //   "trusted-issuers-registry": "v5",
    //   "trusted-policies-registry": "v3",
    //   "trusted-schemas-registry": "v3",
    // },
    // OPTIONAL. Timeout after which the requests made by the library will fail. Default: 15 seconds
    // timeout: 15_000,
    // OPTIONAL. Determines whether to validate the accreditations of the VC issuer or not.
    // Validation is active by default.
    // skipAccreditationsValidation: false,
    // OPTIONAL. Determines whether to validate the credential status or not.
    // Validation is active by default.
    // skipStatusValidation: false,
    // OPTIONAL. Determines whether to validate the credential subject or not
    // Validation is active by default.
    // skipCredentialSubjectValidation: false,
    // OPTIONAL. Unix timestamp. Optional comparison date. Default: current date and time.
    // validAt: Date.now(),
    // OPTIONAL. Credential subject. This parameter is mandatory if the payload's `credentialSubject` is an array.
    // It must correspond to one of the IDs in the payload's `credentialSubject` array.
    // sub: "did:ebsi:z25a23eWUxQQzmAgnD9srpMM",
    // OPTIONAL. Enable Ajv verbose mode (default: false)
    // verbose: false,
    // OPTIONAL. Extra credentialSchema types. By default, the library only supports "FullJsonSchemaValidator2021" and "JsonSchema".
    // The library is not responsible for validating these extra types.
    // extraCredentialSchemaTypes: [],
  };


  // TODO: Resolve signer type per alg
  const signer = ES256KSigner(base64ToBytes(issuer_jwk["d"]));
  const issuer = {
      did: issuer_did,
      kid: issuer_kid,
      alg: resolveAlg(issuer_jwk),
      signer,
  };
  const vcJwt = await createVerifiableCredentialJwt(vcPayload, issuer, options);
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
