import express from "express";
import path from "path";

import { generatePrivateJwk } from "./jwk.js";
import { createDidFromJwk, resolveDid } from "./did.js";
import { issueCredential, verifyCredential } from "./vc.js";
import { resolveAlgorithm } from "./util.js";

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));


app.get("/", (req, res) => {
  res.send("Service is up")
});


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
  const { alg } = req.body;
  if (!alg) {
    return res.status(400).json({ error: "Malformed request: No algorithm specified" });
  }

  let jwk;
  try {
    jwk = await generatePrivateJwk(alg);
  } catch(err) {
    return res.status(400).json({ error: err.message });
  }

  res.json({ jwk })
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


app.get("/issue-vc", async (req, res) => {
  const body = req.body;
  if (!body) {
    return res.status(400).json({ error: "Malformed request: No body" });
  }

  const { issuer, subject } = req.body;
  if (!issuer || !subject) {
    return res.status(400).json({ error: "Both issuer and subject must be provided" });
  }

  const { did: issuer_did, jwk, kid } = issuer;
  const { did: subject_did } = subject;

  if (!issuer_did) {
    return res.status(400).json({ error: "Malformed request: No issuer DID specified" });
  }

  if (!jwk) {
    return res.status(400).json({ error: "Malformed request: No issuer JWK specified" });
  }

  if (!kid) {
    return res.status(400).json({ error: "Malformed request: No issuer kid specified" });
  }

  if (!subject_did) {
    return res.status(400).json({ error: "Malformed request: No subject DID specified" });
  }

  if (resolveAlgorithm(jwk) != "ES256K") {
    return res.status(400).json({ error: "Only secp256k1 keys are allowed to issue!" });
  }

  const token = await issueCredential(jwk, issuer_did, kid, subject_did);
  res.json({ token });
});


app.get("/verify-vc", async (req, res) => {
  const body = req.body;
  if (!body) {
    return res.status(400).json({ error: "Malformed request: No body" });
  }

  const { token } = req.body;
  if (!token) {
    return res.status(400).json({ error: "Malformed request: No VC token provided" });
  }

  const result = await verifyCredential(token);
  res.json( { result });
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

  const result = await resolveDid(body.did);
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
