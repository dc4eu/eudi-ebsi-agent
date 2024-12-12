import server from "../app/server";
import supertest from "supertest";

const client = supertest(server)

describe("Service info endpoint", () => {
  it("GET /info: Should display service info in JSON format", async () => {
    const res = await client.get("/info");
    expect(res.status).toEqual(200);
    expect(res.headers["content-type"]).toMatch("application\/json");
    expect(res.body).toEqual({
      "name": "EBSI Ledger Onboarding Service"
    });
  });
});


describe("DID creation endpoint - success", () => {
  it.each([
    ["rsa", "key"],
    ["rsa", "ebsi"],
    ["ES256K", "key"],
    ["ES256K", "ebsi"],
    ["secp256k1", "key"],
    ["secp256k1", "ebsi"],
  ])(
  "GET /create-did: create both JWK and DID - over: %s, method: %s", async (crypto, method) => {
    const res = await client
      .post("/create-did")
      .send({
        crypto, method
      });
    expect(res.status).toEqual(200);
    const { did, privateJwk, publicJwk } = res.body;
    expect(did.startsWith(`did:${method}`)).toEqual(true);
    expect(privateJwk.kty.toLowerCase()).toEqual(crypto == "rsa" ? crypto : "ec");
    expect(publicJwk.kty.toLowerCase()).toEqual(crypto == "rsa" ? crypto : "ec");
  });
  it.each(["key", "ebsi"])(
    "GET /create-did: create DID from submitted JWK - method: %s", async (method) => {
      const jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": "ngy44T1vxAT6Di4nr-UaM9K3Tlnz9pkoksDokKFkmNc",
        "y": "QCRfOKlSM31GTkb4JHx3nXB4G_jSPMsbdjzlkT_UpPc",
      }
      const res = await client
        .post("/create-did")
        .send({
          jwk, method
        });
      expect(res.status).toEqual(200);
      const { did, privateJwk, publicJwk } = res.body;
      expect(did.startsWith(`did:${method}`)).toEqual(true);
      expect(privateJwk).toEqual(undefined);
      expect(publicJwk).toEqual(jwk);
  });
});

describe("DID creation endpoint - errors", () => {
  it("GET /create-did: 400 - No method specified", async () => {
    const res = await client
      .post("/create-did")
        .send({});
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Malformed request: No method specified"
    });
  });
  it("GET /create-did: 400 - No crypto specified", async () => {
    const res = await client
      .post("/create-did")
        .send({
          "method": "ebsi"
        });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Malformed request: No crypto specified"
    });
  });
  it("GET /create-did: 400 - Unsupported method", async () => {
    const res = await client
      .post("/create-did")
        .send({
          "method": "foo",
          "crypto": "rsa",
        });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Unsupported method: foo"
    });
  });
  it("GET /create-did: 400 - Unsupported crypto", async () => {
    const res = await client
      .post("/create-did")
        .send({
          "method": "foo",
          "crypto": "rsa",
        });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Unsupported method: foo"
    });
  });
});


describe("DID resolution endpoint", () => {
  it("GET /resolve: Malformed request", async () => {
    const res = await client.get("/resolve");
    expect(res.status).toEqual(400);
    expect(res.headers["content-type"]).toMatch("application\/json");
    expect(res.body).toEqual({
      "error": "Malformed request"
    });
  });
  it("GET /resolve: Invalid DID", async () => {
    const res = await client
      .get("/resolve")
      .set('Content-Type', 'application/json')
      .send({
        did: "did:ebsi:666"
      });
    expect(res.status).toEqual(400);
    expect(res.headers["content-type"]).toMatch("application\/json");
    expect(res.body).toEqual({
      "error": "Invalid DID"
    });
  });
  it("GET /resolve: DID not found", async () => {
    const res = await client
      .get("/resolve")
      .set('Content-Type', 'application/json')
      .send({
        did: "did:ebsi:zvHWX359A3CvfJnCYaAiAde"
      });
    expect(res.status).toEqual(400);
    expect(res.headers["content-type"]).toMatch("application\/json");
    expect(res.body).toEqual({
      "error": "DID not found"
    });
  });
  it("GET /resolve: Success", async () => {
    const res = await client
      .get("/resolve")
      .set('Content-Type', 'application/json')
      .send({
        did: "did:ebsi:ziDnioxYYLW1a3qUbqTFz4W"
      });
    expect(res.status).toEqual(200);
    expect(res.headers["content-type"]).toMatch("application\/json");
    expect(res.body).toEqual({
      "didDocument": {
          "@context": [
              "https://www.w3.org/ns/did/v1",
              "https://w3id.org/security/suites/jws-2020/v1"
          ],
          "id": "did:ebsi:ziDnioxYYLW1a3qUbqTFz4W",
          "controller": [
              "did:ebsi:ziDnioxYYLW1a3qUbqTFz4W"
          ],
          "verificationMethod": [
              {
                  "id": "did:ebsi:ziDnioxYYLW1a3qUbqTFz4W#vCF0KgYJJvoSiiDrMdR6BlrOWzzckOm7iFakMDPOSWc",
                  "type": "JsonWebKey2020",
                  "controller": "did:ebsi:ziDnioxYYLW1a3qUbqTFz4W",
                  "publicKeyJwk": {
                      "kty": "EC",
                      "crv": "secp256k1",
                      "x": "Yr5dSC8vVBhz_a_EiIjH63shj1uqPeg8UjtoUXtsVZU",
                      "y": "NicHUkZrnM1GgWn1GO4Dl27Q5rD-kG-ODF_jhZYSyQw"
                  }
              },
              {
                  "id": "did:ebsi:ziDnioxYYLW1a3qUbqTFz4W#f2gYeed1K05Z7kd87u4RPaI9TgJoNNZXo9nh5JsjtGU",
                  "type": "JsonWebKey2020",
                  "controller": "did:ebsi:ziDnioxYYLW1a3qUbqTFz4W",
                  "publicKeyJwk": {
                      "kty": "EC",
                      "crv": "P-256",
                      "x": "wcPJTOaQWzGinDY2XAQ47sWm-7QFUFMuHIdbPrc-I4o",
                      "y": "LNiGME-6qLagfzc5jVzhcBHuMaNRuNTTcS3gxK7ke1U"
                  }
              }
          ],
          "authentication": [
              "did:ebsi:ziDnioxYYLW1a3qUbqTFz4W#vCF0KgYJJvoSiiDrMdR6BlrOWzzckOm7iFakMDPOSWc",
              "did:ebsi:ziDnioxYYLW1a3qUbqTFz4W#f2gYeed1K05Z7kd87u4RPaI9TgJoNNZXo9nh5JsjtGU"
          ],
          "assertionMethod": [
              "did:ebsi:ziDnioxYYLW1a3qUbqTFz4W#f2gYeed1K05Z7kd87u4RPaI9TgJoNNZXo9nh5JsjtGU"
          ],
          "capabilityInvocation": [
              "did:ebsi:ziDnioxYYLW1a3qUbqTFz4W#vCF0KgYJJvoSiiDrMdR6BlrOWzzckOm7iFakMDPOSWc"
          ]
      },
      "didDocumentMetadata": {},
      "didResolutionMetadata": {
          "contentType": "application/did+ld+json"
      }
    });
  });
});
