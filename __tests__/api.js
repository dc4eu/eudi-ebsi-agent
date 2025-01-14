import server from "../app/server";
import { resolveAlgorithm } from "../app/util";
import supertest from "supertest";
import { decodeJWT } from "did-jwt";
import { importJWK, jwtVerify } from "jose";

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


describe("Key creation endpoint - success", () => {
  it.each(["rsa", "secp256k1"])(
  "GET /create-key: 200 - create JWK - over: %s", async (alg) => {
    const res = await client
      .get("/create-key")
      .send({
        alg
      });
    expect(res.status).toEqual(200);
    const { jwk } = res.body;
    expect(jwk.kty.toLowerCase()).toEqual(
      alg.toLowerCase() == "rsa" ? alg.toLowerCase() : "ec"
    );
  });
});

describe("Key creation endpoint - errors", () => {
  it("GET /create-key: 400 - No algorithm specified", async () => {
    const res = await client
      .get("/create-key")
        .send({
        });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Malformed request: No algorithm specified"
    });
  });
  it("GET /create-key: 400 - Unsupported algorithm", async () => {
    const res = await client
      .get("/create-key")
        .send({
          alg: "foo",
        });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Unsupported algorithm: foo"
    });
  });
});


describe("DID creation endpoint - success", () => {
  const publicJwk = {
    "kty": "EC",
    "crv": "P-256",
    "x": "ngy44T1vxAT6Di4nr-UaM9K3Tlnz9pkoksDokKFkmNc",
    "y": "QCRfOKlSM31GTkb4JHx3nXB4G_jSPMsbdjzlkT_UpPc",
  }
  it.each(["key", "ebsi"])(
    "GET /create-did: 200 - create DID - method: %s", async (method) => {
      const res = await client
        .get("/create-did")
        .send({
          publicJwk, method
        });
      expect(res.status).toEqual(200);
      const { did } = res.body;
      expect(did.startsWith(`did:${method}`)).toEqual(true);
  });
});

describe("DID creation endpoint - errors", () => {
  const publicJwk = {
    "kty": "EC",
    "crv": "P-256",
    "x": "ngy44T1vxAT6Di4nr-UaM9K3Tlnz9pkoksDokKFkmNc",
    "y": "QCRfOKlSM31GTkb4JHx3nXB4G_jSPMsbdjzlkT_UpPc",
  }
  it("GET /create-did: 400 - No method specified", async () => {
    const res = await client
      .get("/create-did")
        .send({
          publicJwk
        });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Malformed request: No method specified"
    });
  });
  it("GET /create-did: 400 - Unsupported method", async () => {
    const res = await client
      .get("/create-did")
        .send({
          "method": "foo",
          publicJwk,
        });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Unsupported method: foo"
    });
  });
  it("GET /create-did: 400 - No JWK specified", async () => {
    const res = await client
      .get("/create-did")
        .send({
          "method": "ebsi",
        });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Malformed request: No JWK specified"
    });
  });
});


describe("DID resolution endpoint - success", () => {
  it("GET /resolve-did: 200 - Resolve onboarded DID", async () => {
    const did  = "did:ebsi:ziDnioxYYLW1a3qUbqTFz4W";
    const res = await client
      .get("/resolve-did")
      .set("Content-Type", "application/json")
      .send({
        did
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


describe("DID resolution endpoint - errors", () => {
  it("GET /resolve-did: 400 - No did specified", async () => {
    const res = await client.get("/resolve-did");
    expect(res.status).toEqual(400);
    expect(res.headers["content-type"]).toMatch("application\/json");
    expect(res.body).toEqual({
      "error": "Malformed request: No did specified"
    });
  });
  it("GET /resolve-did: 400 - Invalid DID", async () => {
    const res = await client
      .get("/resolve-did")
      .set("Content-Type", "application/json")
      .send({
        did: "did:ebsi:666"
      });
    expect(res.status).toEqual(400);
    expect(res.headers["content-type"]).toMatch("application\/json");
    expect(res.body).toEqual({
      "error": "Invalid DID"
    });
  });
  it("GET /resolve-did: 400 - DID not found", async () => {
    const res = await client
      .get("/resolve-did")
      .set("Content-Type", "application/json")
      .send({
        did: "did:ebsi:zvHWX359A3CvfJnCYaAiAde"
      });
    expect(res.status).toEqual(400);
    expect(res.headers["content-type"]).toMatch("application\/json");
    expect(res.body).toEqual({
      "error": "DID not found"
    });
  });
});


describe("VC issuance endpoint - success", () => {
  it.each(["secp256k1"])("GET /issue-credential: 200 - issue VC - over: %s", async (alg) => {
    const issuer = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const subject = "did:ebsi:z25a23eWUxQQzmAgnD9srpMM";
    const jwk = require("./fixtures/key_2.json"); // secp256k1
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const res = await client
      .get("/issue-credential")
      .set("Content-Type", "application/json")
      .send({
        issuer,
        subject,
        kid,
        jwk,
      });
    expect(res.status).toEqual(200);
    const { vcJwt } = res.body;

    // Verify embedded signature and parse content
    const publicKey = await importJWK(jwk, resolveAlgorithm(jwk));
    const { payload, protectedHeader: header } = await jwtVerify(vcJwt, publicKey);

    // Check header content
    expect(header.alg).toEqual("ES256K");
    expect(header.kid).toEqual(kid);

    // Check vc content
    const { vc } = payload;
    const now = new Date();
    const after5Years = new Date(now);
    after5Years.setFullYear(now.getFullYear() + 5);
    const after10Years = new Date(now);
    after10Years.setFullYear(now.getFullYear() + 10);
    expect(vc.issuer).toEqual(issuer);
    expect(vc.issuanceDate).toMatch(now.toISOString().split("T")[0]);   // Current date
    expect(vc.validFrom).toMatch(now.toISOString().split("T")[0]);   // 0 seconds after current date
    expect(vc.validUntil).toMatch(after10Years.toISOString().split("T")[0]);   // 10 years after current date
    expect(vc.expirationDate).toMatch(after5Years.toISOString().split("T")[0]);   // 5 years after current date
    expect(vc.issued).toMatch(new Date().toISOString().split("T")[0]);   // Current date
    expect(vc.credentialSubject.id).toEqual(subject);
  });
});


describe("VC issuance endpoint - errors", () => {
  it("GET /issue-credential: 400 - Missing issuer DID", async () => {
    const issuer = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const subject = "did:ebsi:z25a23eWUxQQzmAgnD9srpMM";
    const jwk = require("./fixtures/key_2.json");
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const res = await client
      .get("/issue-credential")
      .set("Content-Type", "application/json")
      .send({
        // issuer,
        subject,
        kid,
        jwk,
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Malformed request: No issuer DID specified"
    });
  });
  it("GET /issue-credential: 400 - Missing issuer JWK", async () => {
    const issuer = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const subject = "did:ebsi:z25a23eWUxQQzmAgnD9srpMM";
    const jwk = require("./fixtures/key_2.json");
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const res = await client
      .get("/issue-credential")
      .set("Content-Type", "application/json")
      .send({
        issuer,
        subject,
        kid,
        // jwk,
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Malformed request: No issuer JWK specified"
    });
  });
  it("GET /issue-credential: 400 - Missing issuer kid", async () => {
    const issuer = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const subject = "did:ebsi:z25a23eWUxQQzmAgnD9srpMM";
    const jwk = require("./fixtures/key_2.json");
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const res = await client
      .get("/issue-credential")
      .set("Content-Type", "application/json")
      .send({
        issuer,
        subject,
        // kid,
        jwk,
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Malformed request: No issuer kid specified"
    });
  });
  it("GET /issue-credential: 400 - Missing subject DID", async () => {
    const issuer = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const subject = "did:ebsi:z25a23eWUxQQzmAgnD9srpMM";
    const jwk = require("./fixtures/key_2.json");
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const res = await client
      .get("/issue-credential")
      .set("Content-Type", "application/json")
      .send({
        issuer,
        // subject,
        kid,
        jwk,
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Malformed request: No subject DID specified"
    });
  });
  it("GET /issue-credential: 400 - Unsupported signing algorithm", async () => {
    const issuer = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const subject = "did:ebsi:z25a23eWUxQQzmAgnD9srpMM";
    const jwk = require("./fixtures/key_1.json"); // rsa
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const res = await client
      .get("/issue-credential")
      .set("Content-Type", "application/json")
      .send({
        issuer,
        subject,
        kid,
        jwk,
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Only secp256k1 keys are allowed to issue!"
    });
  });
});
