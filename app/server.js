import express from "express";
import path from "path";

import { Resolver } from "did-resolver";
import { getResolver } from "@cef-ebsi/ebsi-did-resolver";

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


app.get("/info", (req, res) => {
  res.json({
    "name": "EBSI Ledger Onboarding Service"
  });
});


app.get("/resolve", async (req, res) => {
  const body = req.body;

  if (!(body && body.did)) {
    return res.status(400).json({ error: "Malformed request" });
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
