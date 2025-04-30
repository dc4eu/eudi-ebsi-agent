import server from "../app/server";
import { resolveAlgorithm } from "../app/util";
import supertest from "supertest";
import { decodeJWT } from "did-jwt";
import { importJWK, jwtVerify } from "jose";
import fs from "fs";
import path from "path";

const loadToken = (filename) => {
  let token = fs.readFileSync(path.join(__dirname, filename), {
    encoding: "utf-8", flag: "r"
  });
  return token.replace(/(\r\n|\n|\r)/g, "");  // Take care to remove newline
}

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


describe("JWK creation - success", () => {
  it.each(["rsa", "secp256k1"])(
  "GET /create-key: 200 - create JWK - over: %s", async (alg) => {
    const res = await client
      .post("/create-key")
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

describe("JWK creation - errors", () => {
  it("GET /create-key: 400 - No algorithm provided", async () => {
    const res = await client
      .post("/create-key")
        .send({
        });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No algorithm provided"
    });
  });
  it("GET /create-key: 400 - Unsupported algorithm", async () => {
    const res = await client
      .post("/create-key")
        .send({
          alg: "foo",
        });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Unsupported algorithm: foo"
    });
  });
});


describe("DID creation - success", () => {
  const publicJwk = {
    "kty": "EC",
    "crv": "P-256",
    "x": "ngy44T1vxAT6Di4nr-UaM9K3Tlnz9pkoksDokKFkmNc",
    "y": "QCRfOKlSM31GTkb4JHx3nXB4G_jSPMsbdjzlkT_UpPc",
  }
  it.each(["key", "ebsi"])(
    "GET /create-did: 200 - create DID - method: %s", async (method) => {
      const res = await client
        .post("/create-did")
        .send({
          publicJwk, method
        });
      expect(res.status).toEqual(200);
      const { did } = res.body;
      expect(did.startsWith(`did:${method}`)).toEqual(true);
  });
});

describe("DID creation - errors", () => {
  const publicJwk = {
    "kty": "EC",
    "crv": "P-256",
    "x": "ngy44T1vxAT6Di4nr-UaM9K3Tlnz9pkoksDokKFkmNc",
    "y": "QCRfOKlSM31GTkb4JHx3nXB4G_jSPMsbdjzlkT_UpPc",
  }
  it("GET /create-did: 400 - No method provided", async () => {
    const res = await client
      .post("/create-did")
        .send({
          publicJwk
        });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No method provided"
    });
  });
  it("GET /create-did: 400 - Unsupported method", async () => {
    const res = await client
      .post("/create-did")
        .send({
          "method": "foo",
          publicJwk,
        });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Unsupported method: foo"
    });
  });
  it("GET /create-did: 400 - No JWK provided", async () => {
    const res = await client
      .post("/create-did")
        .send({
          "method": "ebsi",
        });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No JWK provided"
    });
  });
});


describe("DID resolution - success", () => {
  it("GET /resolve-did: 200 - Resolve onboarded DID", async () => {
    const did  = "did:ebsi:ziDnioxYYLW1a3qUbqTFz4W";
    const res = await client
      .post("/resolve-did")
      .set("Content-Type", "application/json")
      .send({
        did
      });
    expect(res.status).toEqual(200);
    expect(res.headers["content-type"]).toMatch("application\/json");
    expect(res.body).toEqual(require("./fixtures/did-doc.json"));
  });
});


describe("DID resolution - errors", () => {
  it("GET /resolve-did: 400 - No DID provided", async () => {
    const res = await client.post("/resolve-did");
    expect(res.status).toEqual(400);
    expect(res.headers["content-type"]).toMatch("application\/json");
    expect(res.body).toEqual({
      "error": "Bad request: No did provided"
    });
  });
  it("GET /resolve-did: 400 - Invalid DID", async () => {
    const res = await client
      .post("/resolve-did")
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
      .post("/resolve-did")
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


describe("VC issuance - success", () => {
  it.each(["secp256k1"])("GET /issue-vc: 200 - issue VC - over: %s", async (alg) => {
    const issuerDid = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const subjectDid = "did:ebsi:z25a23eWUxQQzmAgnD9srpMM";
    const jwk = require("./fixtures/jwk-2.json"); // secp256k1
    const claims = {
      firstName: "Yahya",
      familyName: "Sinwar",
      dateOfBirth: "1962-10-29",
      personalIdentifier: "666999",
      placeOfBirth: {
        addressLocality: "Khan Yunis",
      },
      gender: "unspecified",
      ageOver18: true,
    };
    const res = await client
      .post("/issue-vc")
      .set("Content-Type", "application/json")
      .send({
        issuer: {
          did: issuerDid,
          kid,
          jwk,
        },
        subject: {
          did: subjectDid
        },
        claims,
      });
    expect(res.status).toEqual(200);
    const { token } = res.body;

    // Verify embedded signature and parse content
    const publicKey = await importJWK(jwk, resolveAlgorithm(jwk));
    const { payload, protectedHeader: header } = await jwtVerify(token, publicKey);

    // Check header content
    expect(header.alg).toEqual("ES256K");
    expect(header.kid).toEqual(`${issuerDid}#${kid}`);

    // Check vc content
    const { vc } = payload;
    const now = new Date();
    const after5Years = new Date(now);
    after5Years.setFullYear(now.getFullYear() + 5);
    const after10Years = new Date(now);
    after10Years.setFullYear(now.getFullYear() + 10);
    expect(vc.issuer).toEqual(issuerDid);
    expect(vc.issuanceDate).toMatch(now.toISOString().split("T")[0]);   // Current date
    expect(vc.validFrom).toMatch(now.toISOString().split("T")[0]);   // 0 seconds after current date
    expect(vc.validUntil).toMatch(after10Years.toISOString().split("T")[0]);   // 10 years after current date
    expect(vc.expirationDate).toMatch(after5Years.toISOString().split("T")[0]);   // 5 years after current date
    expect(vc.issued).toMatch(new Date().toISOString().split("T")[0]);   // Current date
    expect(vc.credentialSubject).toEqual({
      id: subjectDid, ...claims
    });
  });
});


describe("VC issuance - errors", () => {
  it("GET /issue-vc: 400 - Missing issuer DID", async () => {
    const issuerDid = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const subjectDid = "did:ebsi:z25a23eWUxQQzmAgnD9srpMM";
    const jwk = require("./fixtures/jwk-2.json"); // secp256k1
    const claims = { a: 0, b: 1 };
    const res = await client
      .post("/issue-vc")
      .set("Content-Type", "application/json")
      .send({
        issuer: {
          // did: issuerDid,
          kid,
          jwk,
        },
        subject: {
          did: subjectDid
        },
        claims,
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No issuer provided"
    });
  });
  it("GET /issue-vc: 400 - Missing issuer JWK", async () => {
    const issuerDid = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const subjectDid = "did:ebsi:z25a23eWUxQQzmAgnD9srpMM";
    const jwk = require("./fixtures/jwk-2.json"); // secp256k1
    const claims = { a: 0, b: 1 };
    const res = await client
      .post("/issue-vc")
      .set("Content-Type", "application/json")
      .send({
        issuer: {
          did: issuerDid,
          kid,
          // jwk,
        },
        subject: {
          did: subjectDid
        },
        claims,
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No issuer JWK provided"
    });
  });
  it("GET /issue-vc: 400 - Missing issuer kid", async () => {
    const issuerDid = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const subjectDid = "did:ebsi:z25a23eWUxQQzmAgnD9srpMM";
    const jwk = require("./fixtures/jwk-2.json"); // secp256k1
    const claims = { a: 0, b: 1 };
    const res = await client
      .post("/issue-vc")
      .set("Content-Type", "application/json")
      .send({
        issuer: {
          did: issuerDid,
          // kid,
          jwk,
        },
        subject: {
          did: subjectDid
        },
        claims,
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No issuer kid provided"
    });
  });
  it("GET /issue-vc: 400 - Missing subject DID", async () => {
    const issuerDid = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const subjectDid = "did:ebsi:z25a23eWUxQQzmAgnD9srpMM";
    const jwk = require("./fixtures/jwk-2.json"); // secp256k1
    const claims = { a: 0, b: 1 };
    const res = await client
      .post("/issue-vc")
      .set("Content-Type", "application/json")
      .send({
        issuer: {
          did: issuerDid,
          kid,
          jwk,
        },
        subject: {
          // did: subjectDid
        },
        claims,
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No subject provided"
    });
  });
  it("GET /issue-vc: 400 - Missing claims", async () => {
    const issuerDid = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const subjectDid = "did:ebsi:z25a23eWUxQQzmAgnD9srpMM";
    const jwk = require("./fixtures/jwk-2.json"); // secp256k1
    const claims = { a: 0, b: 1 };
    const res = await client
      .post("/issue-vc")
      .set("Content-Type", "application/json")
      .send({
        issuer: {
          did: issuerDid,
          kid,
          jwk,
        },
        subject: {
          did: subjectDid
        },
        // claims,
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No claims provided"
    });
  });
  it("GET /issue-vc: 400 - Unsupported signing algorithm", async () => {
    const issuerDid = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const subjectDid = "did:ebsi:z25a23eWUxQQzmAgnD9srpMM";
    const jwk = require("./fixtures/jwk-1.json"); // secp256k1
    const res = await client
      .post("/issue-vc")
      .set("Content-Type", "application/json")
      .send({
        issuer: {
          did: issuerDid,
          kid,
          jwk,
        },
        subject: {
          did: subjectDid
        }
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Only secp256k1 keys are allowed to issue!"
    });
  });
});


describe("VC verification - success", () => {
  // TODO
  it.each([
    "./fixtures/vc-1.jwt",
  ])("GET /verify-vc: 200 - verify VC: %s", async (vc_file) => {
    const token = loadToken(vc_file);
    const res = await client
      .post("/verify-vc")
      .set("Content-Type", "application/json")
      .send({
        token
      });
    expect(res.status).toEqual(200);
    expect(res.body.vcDocument).toEqual(require("./fixtures/vc-doc.json"));
  });
});


describe("VC verification - errors", () => {
  it("GET /verify-vc: 400 - Missing VC token", async () => {
    const res = await client
      .post("/verify-vc")
      .set("Content-Type", "application/json")
      .send({
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No VC token provided"
    });
  });
  it("GET /verify-vc: 400 - Invalid VC token", async () => {
    let token = loadToken("fixtures/vc-1.jwt");
    token += "?";   // Tamper signature
    const res = await client
      .post("/verify-vc")
      .set("Content-Type", "application/json")
      .send({
        token
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      error: {
        message: "Unable to decode JWT VC",
        name: "ValidationError",
      }
    });
  });
});


describe("VP issuance - success", () => {
  it.each(["secp256k1"])("GET /issue-vp: 200 - issue VP - over: %s", async (alg) => {
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const signerDid   = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const holderDid   = "did:ebsi:z21Y3pwhoDsJAzHTHAMV3k4S";
    const audienceDid = "did:ebsi:zwNAE5xThBpmGJUWAY23kgx";
    const vc_1 = loadToken("fixtures/vc-1.jwt")
    const vc_2 = loadToken("fixtures/vc-2.jwt")
    const jwk = require("./fixtures/jwk-2.json"); // secp256k1
    const res = await client
      .post("/issue-vp")
      .set("Content-Type", "application/json")
      .send({
        signer: {
          did: signerDid,
          kid,
          jwk,
        },
        holder: {
          did: holderDid,
        },
        audience: {
          did: audienceDid,
        },
        credentials: [
          vc_1,
          vc_2,
        ]
      });
    expect(res.status).toEqual(200);
    const { token } = res.body;

    // Verify embedded signature and parse content
    const publicKey = await importJWK(jwk, resolveAlgorithm(jwk));
    const { payload, protectedHeader: header } = await jwtVerify(token, publicKey);

    // Check header content
    expect(header.alg).toEqual("ES256K");
    expect(header.kid).toEqual(kid);

    // Check vp content
    const { iss, sub, aud, vp } = payload;
    expect(iss).toEqual(signerDid);
    expect(sub).toEqual(signerDid);
    expect(aud).toEqual(audienceDid);
    expect(vp.holder).toEqual(holderDid);
    expect(vp.verifiableCredential).toEqual([
      vc_1,
      vc_2,
    ]);
  });
});

describe("VP issuance - errors", () => {
  it("GET /issue-vp: 400 - Missing signer DID", async () => {
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const signerDid   = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const holderDid   = "did:ebsi:z21Y3pwhoDsJAzHTHAMV3k4S";
    const audienceDid = "did:ebsi:zwNAE5xThBpmGJUWAY23kgx";
    const vc_1 = loadToken("fixtures/vc-1.jwt")
    const vc_2 = loadToken("fixtures/vc-2.jwt")
    const jwk = require("./fixtures/jwk-2.json"); // secp256k1
    const res = await client
      .post("/issue-vp")
      .set("Content-Type", "application/json")
      .send({
        signer: {
          // did: signerDid,
          kid,
          jwk,
        },
        holder: {
          did: holderDid
        },
        audience: {
          did: audienceDid,
        },
        credentials: [
          vc_1,
          vc_2,
        ]
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No signer provided"
    });
  });
  it("GET /issue-vp: 400 - Missing signer JWK", async () => {
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const signerDid   = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const holderDid   = "did:ebsi:z21Y3pwhoDsJAzHTHAMV3k4S";
    const audienceDid = "did:ebsi:zwNAE5xThBpmGJUWAY23kgx";
    const vc_1 = loadToken("fixtures/vc-1.jwt")
    const vc_2 = loadToken("fixtures/vc-2.jwt")
    const jwk = require("./fixtures/jwk-2.json"); // secp256k1
    const res = await client
      .post("/issue-vp")
      .set("Content-Type", "application/json")
      .send({
        signer: {
          did: signerDid,
          kid,
          // jwk,
        },
        holder: {
          did: holderDid
        },
        audience: {
          did: audienceDid,
        },
        credentials: [
          vc_1,
          vc_2,
        ]
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No signer JWK provided"
    });
  });
  it("GET /issue-vp: 400 - Missing signer kid", async () => {
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const signerDid   = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const holderDid   = "did:ebsi:z21Y3pwhoDsJAzHTHAMV3k4S";
    const audienceDid = "did:ebsi:zwNAE5xThBpmGJUWAY23kgx";
    const vc_1 = loadToken("fixtures/vc-1.jwt")
    const vc_2 = loadToken("fixtures/vc-2.jwt")
    const jwk = require("./fixtures/jwk-2.json"); // secp256k1
    const res = await client
      .post("/issue-vp")
      .set("Content-Type", "application/json")
      .send({
        signer: {
          did: signerDid,
          // kid,
          jwk,
        },
        holder: {
          did: holderDid
        },
        audience: {
          did: audienceDid,
        },
        credentials: [
          vc_1,
          vc_2,
        ]
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No signer kid provided"
    });
  });
  it("GET /issue-vp: 400 - Missing holder DID", async () => {
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const signerDid   = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const holderDid   = "did:ebsi:z21Y3pwhoDsJAzHTHAMV3k4S";
    const audienceDid = "did:ebsi:zwNAE5xThBpmGJUWAY23kgx";
    const vc_1 = loadToken("fixtures/vc-1.jwt")
    const vc_2 = loadToken("fixtures/vc-2.jwt")
    const jwk = require("./fixtures/jwk-2.json"); // secp256k1
    const res = await client
      .post("/issue-vp")
      .set("Content-Type", "application/json")
      .send({
        signer: {
          did: signerDid,
          kid,
          jwk,
        },
        holder: {
          // did: holderDid
        },
        audience: {
          did: audienceDid,
        },
        credentials: [
          vc_1,
          vc_2,
        ]
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No holder provided"
    });
  });
  it("GET /issue-vp: 400 - Missing audience DID", async () => {
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const signerDid   = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const holderDid   = "did:ebsi:z21Y3pwhoDsJAzHTHAMV3k4S";
    const audienceDid = "did:ebsi:zwNAE5xThBpmGJUWAY23kgx";
    const vc_1 = loadToken("fixtures/vc-1.jwt")
    const vc_2 = loadToken("fixtures/vc-2.jwt")
    const jwk = require("./fixtures/jwk-2.json"); // secp256k1
    const res = await client
      .post("/issue-vp")
      .set("Content-Type", "application/json")
      .send({
        signer: {
          did: signerDid,
          kid,
          jwk,
        },
        holder: {
          did: holderDid
        },
        audience: {
          // did: audienceDid,
        },
        credentials: [
          vc_1,
          vc_2,
        ]
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No audience provided"
    });
  });
  it("GET /issue-vp: 400 - Missing credentials", async () => {
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const signerDid   = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const holderDid   = "did:ebsi:z21Y3pwhoDsJAzHTHAMV3k4S";
    const audienceDid = "did:ebsi:zwNAE5xThBpmGJUWAY23kgx";
    const vc_1 = loadToken("fixtures/vc-1.jwt")
    const vc_2 = loadToken("fixtures/vc-2.jwt")
    const jwk = require("./fixtures/jwk-2.json"); // secp256k1
    const res = await client
      .post("/issue-vp")
      .set("Content-Type", "application/json")
      .send({
        signer: {
          did: signerDid,
          kid,
          jwk,
        },
        holder: {
          did: holderDid
        },
        audience: {
          did: audienceDid,
        },
        credentials: [
          // vc_1,
          // vc_2,
        ]
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No VCs provided"
    });
  });
  it("GET /issue-vp: 400 - Unsupported signing algorithm", async () => {
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const signerDid   = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const holderDid   = "did:ebsi:z21Y3pwhoDsJAzHTHAMV3k4S";
    const audienceDid = "did:ebsi:zwNAE5xThBpmGJUWAY23kgx";
    const vc_1 = loadToken("fixtures/vc-1.jwt")
    const vc_2 = loadToken("fixtures/vc-2.jwt")
    const jwk = require("./fixtures/jwk-1.json"); // rsa
    const res = await client
      .post("/issue-vp")
      .set("Content-Type", "application/json")
      .send({
        signer: {
          did: signerDid,
          kid,
          jwk,
        },
        holder: {
          did: holderDid
        },
        audience: {
          did: audienceDid,
        },
        credentials: [
          vc_1,
          vc_2,
        ]
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Only secp256k1 keys are allowed to sign!"
    });
  });
});

describe("VP verification - success", () => {
  it.each([
    "./fixtures/vp.jwt",
  ])("GET /verify-vp: 200 - verify VP: %s", async (vp_file) => {
    const audienceDid = "did:ebsi:zwNAE5xThBpmGJUWAY23kgx";
    const token = loadToken(vp_file);
    const res = await client
      .post("/verify-vp")
      .set("Content-Type", "application/json")
      .send({
        token,
        audience: {
          did: audienceDid,
        }
      });
    expect(res.status).toEqual(200);
    expect(res.body.vpDocument).toEqual(require("./fixtures/vp-doc.json"));
  });
});


describe("VP verification - errors", () => {
  it("GET /verify-vp: 400 - Missing VP token", async () => {
    const res = await client
      .post("/verify-vp")
      .set("Content-Type", "application/json")
      .send({
        audience: {
          did: "whatever",
        }
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No VP token provided"
    });
  });
  it("GET /verify-vp: 400 - Missing audience", async () => {
    const res = await client
      .post("/verify-vp")
      .set("Content-Type", "application/json")
      .send({
        token: "whatever"
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No audience provided"
    });
  });
  it("GET /verify-vp: 400 - Invalid VP token", async () => {
    const audienceDid = "did:ebsi:zwNAE5xThBpmGJUWAY23kgx";
    let token = loadToken("./fixtures/vp.jwt");
    token += "?";   // Tamper signature
    const res = await client
      .post("/verify-vp")
      .set("Content-Type", "application/json")
      .send({
        token,
        audience: {
          did: audienceDid,
        }
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      error: {
        message: "Unable to decode JWT VC",
        name: "ValidationError",
      }
    });
  });
});

