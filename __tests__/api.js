import server from "../app/server";
import supertest from "supertest";

const client = supertest(server)

describe("Info endpoint", () => {
  it("GET /info: Should display service info in JSON format", async () => {
    const res = await client.get("/info");
    expect(res.status).toEqual(200);
    expect(res.headers["content-type"]).toMatch("application\/json");
    expect(res.body).toEqual({
      "name": "EBSI Ledger Onboarding Service"
    });
  });
});


describe("Resolution endpoint", () => {
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
