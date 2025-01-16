import express from "express";
import path from "path";

import { generatePrivateJwk } from "./jwk.js";
import { createDidFromJwk, resolveDid } from "./did.js";
import { issueCredential, verifyCredential } from "./vc.js";
import { createPresentation, verifyPresentation } from "./vp.js";
import { resolveAlgorithm } from "./util.js";
import { decodeJWT, verifyJWT, } from "did-jwt";

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
    return res.status(400).json({ error: "Bad request: No body" });
  }
  const { alg } = req.body;
  if (!alg) {
    return res.status(400).json({ error: "Bad request: No algorithm provided" });
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
    return res.status(400).json({ error: "Bad request: No body" });
  }
  const { method, publicJwk } = req.body;

  if (!method) {
    return res.status(400).json({ error: "Bad request: No method provided" });
  }
  if (!publicJwk) {
    return res.status(400).json({ error: "Bad request: No JWK provided" });
  }

  let did;
  try {
    did = await createDidFromJwk(method, publicJwk);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  res.json({ did });
});


app.get("/resolve-did", async (req, res) => {
  const body = req.body;
  if (!body) {
    return res.status(400).json({ error: "Bad request: No body" });
  }
  const { did } = body;
  if (!did) {
    return res.status(400).json({ error: "Bad request: No did provided" });
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


app.get("/issue-vc", async (req, res) => {
  const body = req.body;
  if (!body) {
    return res.status(400).json({ error: "Bad request: No body" });
  }

  const { issuer, subject } = req.body;
  if (!issuer || !issuer.did) {
    return res.status(400).json({ error: "Bad request: No issuer provided" });
  }
  if (!subject || !subject.did) {
    return res.status(400).json({ error: "Bad request: No subject provided" });
  }

  if (!issuer.jwk) {
    return res.status(400).json({ error: "Bad request: No issuer JWK provided" });
  }
  if (resolveAlgorithm(issuer.jwk) != "ES256K") {
    return res.status(400).json({ error: "Only secp256k1 keys are allowed to issue!" });
  }
  if (!issuer.kid) {
    return res.status(400).json({ error: "Bad request: No issuer kid provided" });
  }

  const token = await issueCredential(issuer.jwk, issuer.kid, issuer.did, subject.did);

  res.json({ token });
});


app.get("/verify-vc", async (req, res) => {
  const body = req.body;
  if (!body) {
    return res.status(400).json({ error: "Bad request: No body" });
  }

  const { token } = req.body;
  if (!token) {
    return res.status(400).json({ error: "Bad request: No VC token provided" });
  }

  const result = await verifyCredential(token);
  res.json( { result });
});


app.get("/issue-vp", async (req, res) => {
  const body = req.body;
  if (!body) {
    return res.status(400).json({ error: "Bad request: No body" });
  }

  const { signer, holder, audience, credentials } = req.body;
  if (!signer || !signer.did) {
    return res.status(400).json({ error: "Bad request: No signer provided" });
  }
  if (!holder || !holder.did) {
    return res.status(400).json({ error: "Bad request: No holder provided" });
  }
  if (!audience || !audience.did) {
    return res.status(400).json({ error: "Bad request: No audience provided" });
  }
  if (!credentials || credentials.length == 0) {
    return res.status(400).json({ error: "No VCs provided" });
  }

  if (!signer.jwk) {
    return res.status(400).json({ error: "Bad request: No signer JWK provided" });
  }
  if (resolveAlgorithm(signer.jwk) != "ES256K") {
    return res.status(400).json({ error: "Only secp256k1 keys are allowed to sign!" });
  }

  if (!signer.kid) {
    return res.status(400).json({ error: "Bad request: No signer kid provided" });
  }

  const token = await createPresentation(signer.jwk, signer.kid, signer.did, holder.did,
                                          audience.did, credentials);
  res.json({ token });
});


const hostname = "0.0.0.0";
const port = process.env.PORT || 1337;
app.listen(port, hostname, () => {
  console.log(`Server listening at port: ${port}`)
})


export default app;
