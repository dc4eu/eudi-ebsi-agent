import server from "../app/server";
import { resolveAlgorithm } from "../app/util";
import supertest from "supertest";
import { decodeJWT } from "did-jwt";
import { importJWK, jwtVerify } from "jose";
import fs from "fs";
import path from "path";

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


describe("JWK creation endpoint - success", () => {
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

describe("JWK creation endpoint - errors", () => {
  it("GET /create-key: 400 - No algorithm provided", async () => {
    const res = await client
      .get("/create-key")
        .send({
        });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No algorithm provided"
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
  it("GET /create-did: 400 - No method provided", async () => {
    const res = await client
      .get("/create-did")
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
  it("GET /create-did: 400 - No JWK provided", async () => {
    const res = await client
      .get("/create-did")
        .send({
          "method": "ebsi",
        });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No JWK provided"
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
    expect(res.body).toEqual(require("./fixtures/resolved.json"));
  });
});


describe("DID resolution endpoint - errors", () => {
  it("GET /resolve-did: 400 - No DID provided", async () => {
    const res = await client.get("/resolve-did");
    expect(res.status).toEqual(400);
    expect(res.headers["content-type"]).toMatch("application\/json");
    expect(res.body).toEqual({
      "error": "Bad request: No did provided"
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
  it.each(["secp256k1"])("GET /issue-vc: 200 - issue VC - over: %s", async (alg) => {
    const issuerDid = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const subjectDid = "did:ebsi:z25a23eWUxQQzmAgnD9srpMM";
    const jwk = require("./fixtures/key_2.json"); // secp256k1
    const res = await client
      .get("/issue-vc")
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
    expect(res.status).toEqual(200);
    const { token } = res.body;

    // Verify embedded signature and parse content
    const publicKey = await importJWK(jwk, resolveAlgorithm(jwk));
    const { payload, protectedHeader: header } = await jwtVerify(token, publicKey);

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
    expect(vc.issuer).toEqual(issuerDid);
    expect(vc.issuanceDate).toMatch(now.toISOString().split("T")[0]);   // Current date
    expect(vc.validFrom).toMatch(now.toISOString().split("T")[0]);   // 0 seconds after current date
    expect(vc.validUntil).toMatch(after10Years.toISOString().split("T")[0]);   // 10 years after current date
    expect(vc.expirationDate).toMatch(after5Years.toISOString().split("T")[0]);   // 5 years after current date
    expect(vc.issued).toMatch(new Date().toISOString().split("T")[0]);   // Current date
    expect(vc.credentialSubject.id).toEqual(subjectDid);
  });
});


describe("VC issuance endpoint - errors", () => {
  it("GET /issue-vc: 400 - Missing issuer DID", async () => {
    const issuerDid = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const subjectDid = "did:ebsi:z25a23eWUxQQzmAgnD9srpMM";
    const jwk = require("./fixtures/key_2.json"); // secp256k1
    const res = await client
      .get("/issue-vc")
      .set("Content-Type", "application/json")
      .send({
        issuer: {
          // did: issuerDid,
          kid,
          jwk,
        },
        subject: {
          did: subjectDid
        }
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
    const jwk = require("./fixtures/key_2.json"); // secp256k1
    const res = await client
      .get("/issue-vc")
      .set("Content-Type", "application/json")
      .send({
        issuer: {
          did: issuerDid,
          kid,
          // jwk,
        },
        subject: {
          did: subjectDid
        }
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
    const jwk = require("./fixtures/key_2.json"); // secp256k1
    const res = await client
      .get("/issue-vc")
      .set("Content-Type", "application/json")
      .send({
        issuer: {
          did: issuerDid,
          // kid,
          jwk,
        },
        subject: {
          did: subjectDid
        }
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
    const jwk = require("./fixtures/key_2.json"); // secp256k1
    const res = await client
      .get("/issue-vc")
      .set("Content-Type", "application/json")
      .send({
        issuer: {
          did: issuerDid,
          kid,
          jwk,
        },
        subject: {
          // did: subjectDid
        }
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No subject provided"
    });
  });
  it("GET /issue-vc: 400 - Unsupported signing algorithm", async () => {
    const issuerDid = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const subjectDid = "did:ebsi:z25a23eWUxQQzmAgnD9srpMM";
    const jwk = require("./fixtures/key_1.json"); // secp256k1
    const res = await client
      .get("/issue-vc")
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


describe("VC verification endpoint - success", () => {
  it.each([
    "./fixtures/vc.jwt",
  ])("GET /verify-vc: 200 - verify VC: %s", async (vc_file) => {
    let token = fs.readFileSync(path.join(__dirname, vc_file), {
      encoding: "utf-8", flag: "r"
    });
    token = token.replace(/(\r\n|\n|\r)/g, "");  // Take care to remove newline
    const res = await client
      .get("/verify-vc")
      .set("Content-Type", "application/json")
      .send({
        token
      });
    expect(res.status).toEqual(200);
    expect(res.body.vcDocument).toEqual(require("./fixtures/vc.retrieved.json"));
  });
});


describe("VC verification endpoint - errors", () => {
  it("GET /verify-vc: 400 - Missing VC token", async () => {
    const res = await client
      .get("/verify-vc")
      .set("Content-Type", "application/json")
      .send({
      });
    expect(res.status).toEqual(400);
    expect(res.body).toEqual({
      "error": "Bad request: No VC token provided"
    });
  });
  it("GET /verify-vc: 400 - Invalid VC token", async () => {
    const vc_file = "./fixtures/vc.jwt";
    let token = fs.readFileSync(path.join(__dirname, vc_file), {
      encoding: "utf-8", flag: "r"
    });
    token = token.replace(/(\r\n|\n|\r)/g, "");  // Take care to remove newline
    token += "?";   // Tamper signature
    const res = await client
      .get("/verify-vc")
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


describe("VP issuance endpoint - success", () => {
  it.each(["secp256k1"])("GET /issue-vp: 200 - issue VP - over: %s", async (alg) => {
    const signerDid = "did:ebsi:zxaYaUtb8pvoAtYNWbKcveg";
    const kid = "CHxYzOqt38Sx6YBfPYhiEdgcwzWk9ty7k0LBa6h70nc";
    const holderDid = "did:key:zBhBLmYmyihtomRdJJNEKzbPj51o4a3GYFeZoRHSABKUwqdjiQPY2cq3LTGRq36RhoZRqix1eq4uA433QJayHdTi8sxm8qdbAbnTyg9dsXCjD8NN7Etcr4f55mRhn9T1d3d6Ec6HgtpcUfemb4ZVKSCDaBrBydsrKAB3TKWNXAkgnz1hseeqf8Y"; // TODO
    const audienceDid = "did:ebsi:zwNAE5xThBpmGJUWAY23kgx";  // TODO
      const vc1 = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QiLCJraWQiOiJkaWQ6ZWJzaTp6eGFZYVV0Yjhwdm9BdFlOV2JLY3ZlZyNDSHhZek9xdDM4U3g2WUJmUFloaUVkZ2N3eldrOXR5N2swTEJhNmg3MG5jIn0.eyJqdGkiOiJ1cm46dXVpZDowMDNhMWRkOC1hNWQyLTQyZWYtODE4Mi1lOTIxYzBhOWYyY2QiLCJzdWIiOiJkaWQ6a2V5OnpCaEJMbVlteWlodG9tUmRKSk5FS3piUGo1MW80YTNHWUZlWm9SSFNBQktVd3FkamlRUFkyY3EzTFRHUnEzNlJob1pScWl4MWVxNHVBNDMzUUpheUhkVGk4c3htOHFkYkFiblR5Zzlkc1hDakQ4Tk43RXRjcjRmNTVtUmhuOVQxZDNkNkVjNkhndHBjVWZlbWI0WlZLU0NEYUJyQnlkc3JLQUIzVEtXTlhBa2duejFoc2VlcWY4WSIsImlzcyI6ImRpZDplYnNpOnp4YVlhVXRiOHB2b0F0WU5XYktjdmVnIiwibmJmIjoxNjM1NzI0ODAwLCJleHAiOjE5NTM3NjMyMDAsImlhdCI6MTU5MjgzNTEwNCwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiaWQiOiJ1cm46dXVpZDowMDNhMWRkOC1hNWQyLTQyZWYtODE4Mi1lOTIxYzBhOWYyY2QiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVmVyaWZpYWJsZUF0dGVzdGF0aW9uIl0sImlzc3VlciI6ImRpZDplYnNpOnp4YVlhVXRiOHB2b0F0WU5XYktjdmVnIiwiaXNzdWFuY2VEYXRlIjoiMjAyMS0xMS0wMVQwMDowMDowMFoiLCJ2YWxpZEZyb20iOiIyMDIxLTExLTAxVDAwOjAwOjAwWiIsInZhbGlkVW50aWwiOiIyMDUwLTExLTAxVDAwOjAwOjAwWiIsImV4cGlyYXRpb25EYXRlIjoiMjAzMS0xMS0zMFQwMDowMDowMFoiLCJpc3N1ZWQiOiIyMDIwLTA2LTIyVDE0OjExOjQ0WiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6QmhCTG1ZbXlpaHRvbVJkSkpORUt6YlBqNTFvNGEzR1lGZVpvUkhTQUJLVXdxZGppUVBZMmNxM0xUR1JxMzZSaG9aUnFpeDFlcTR1QTQzM1FKYXlIZFRpOHN4bThxZGJBYm5UeWc5ZHNYQ2pEOE5ON0V0Y3I0ZjU1bVJobjlUMWQzZDZFYzZIZ3RwY1VmZW1iNFpWS1NDRGFCckJ5ZHNyS0FCM1RLV05YQWtnbnoxaHNlZXFmOFkifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vYXBpLXBpbG90LmVic2kuZXUvdHJ1c3RlZC1zY2hlbWFzLXJlZ2lzdHJ5L3YzL3NjaGVtYXMvejNNZ1VGVWtiNzIydXE0eDNkdjV5QUptbk5tekRGZUs1VUM4eDgzUW9lTEpNIiwidHlwZSI6IkZ1bGxKc29uU2NoZW1hVmFsaWRhdG9yMjAyMSJ9LCJ0ZXJtc09mVXNlIjp7ImlkIjoiaHR0cHM6Ly9hcGktcGlsb3QuZWJzaS5ldS90cnVzdGVkLWlzc3VlcnMtcmVnaXN0cnkvdjUvaXNzdWVycy9kaWQ6ZWJzaTp6eGFZYVV0Yjhwdm9BdFlOV2JLY3ZlZy9hdHRyaWJ1dGVzL2I0MGZkOWI0MDQ0MThhNDRkMmQ5OTExMzc3YTAzMTMwZGRlNDUwZWI1NDZjNzU1YjViODBhY2Q3ODI5MDJlNmQiLCJ0eXBlIjoiSXNzdWFuY2VDZXJ0aWZpY2F0ZSJ9fX0.fKCREswG43_862Vr8L3lJORgFNzvMZ2hR7p93gfEkhM-qhIIlSlP0AcAgy0c6qu2_2uAIC7mOGnj9AZ3Au2nLw";
      const vc2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZWJzaTp6eGFZYVV0Yjhwdm9BdFlOV2JLY3ZlZyNDSHhZek9xdDM4U3g2WUJmUFloaUVkZ2N3eldrOXR5N2swTEJhNmg3MG5jIn0.eyJpYXQiOjE3MDU1NjU1ODksImV4cCI6MTk1Mzc2MzIwMCwianRpIjoidXJuOnV1aWQ6NzQxOWMxMDktMjg1YS00MjRkLWJiNjktMGJhYmFjNmJkNDQ0Iiwic3ViIjoiZGlkOmtleTp6QmhCTG1ZbXlpaHRvbVJkSkpORUt6YlBqNTFvNGEzR1lGZVpvUkhTQUJLVXdxZGppUVBZMmVlNHZjeHY3c3dFdGhhQXdzYVVUbW02cVdaa0drekJRZEZQQmtUcVhwdTVQZWNrdGF5Y1U0cWE4QjdjVWkyeVZoRjF2ejJQOWQ5N1pQdkFrcUc1YTdwVlZWVTZQVFNUZlAyNDRCdEhOa1BVVjk3aXFGR2REUlR5dUxpemV1VXhRdGsiLCJpc3MiOiJkaWQ6ZWJzaTp6eGFZYVV0Yjhwdm9BdFlOV2JLY3ZlZyIsIm5iZiI6MTcwNTU2NTU4OSwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiaWQiOiJ1cm46dXVpZDo3NDE5YzEwOS0yODVhLTQyNGQtYmI2OS0wYmFiYWM2YmQ0NDQiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVmVyaWZpYWJsZUF0dGVzdGF0aW9uIl0sImlzc3VlciI6ImRpZDplYnNpOnp4YVlhVXRiOHB2b0F0WU5XYktjdmVnIiwiaXNzdWFuY2VEYXRlIjoiMjAyNC0wMS0xOFQwODoxMzowOVoiLCJpc3N1ZWQiOiIyMDI0LTAxLTE4VDA4OjEzOjA5WiIsInZhbGlkRnJvbSI6IjIwMjQtMDEtMThUMDg6MTM6MDlaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6a2V5OnpCaEJMbVlteWlodG9tUmRKSk5FS3piUGo1MW80YTNHWUZlWm9SSFNBQktVd3FkamlRUFkyZWU0dmN4djdzd0V0aGFBd3NhVVRtbTZxV1prR2t6QlFkRlBCa1RxWHB1NVBlY2t0YXljVTRxYThCN2NVaTJ5VmhGMXZ6MlA5ZDk3WlB2QWtxRzVhN3BWVlZVNlBUU1RmUDI0NEJ0SE5rUFVWOTdpcUZHZERSVHl1TGl6ZXVVeFF0ayIsImZhbWlseU5hbWUiOiJEdWJvaXMiLCJmaXJzdE5hbWUiOiJTb3BoaWUiLCJkYXRlT2ZCaXJ0aCI6IjE5ODUtMDUtMjAiLCJwZXJzb25hbElkZW50aWZpZXIiOiI5ODc2NTQzMjEiLCJwbGFjZU9mQmlydGgiOnsiYWRkcmVzc0NvdW50cnkiOiJCRSIsImFkZHJlc3NSZWdpb24iOiJCUlUiLCJhZGRyZXNzTG9jYWxpdHkiOiJCcnVzc2VscyJ9LCJjdXJyZW50QWRkcmVzcyI6eyJhZGRyZXNzQ291bnRyeSI6IkJFIiwiYWRkcmVzc1JlZ2lvbiI6IlZCUiIsImFkZHJlc3NMb2NhbGl0eSI6IkxldXZlbiIsInBvc3RhbENvZGUiOiIzMDAwIiwic3RyZWV0QWRkcmVzcyI6IjQ1NiBFbG0gQXZlIiwiZnVsbEFkZHJlc3MiOiI0NTYgRWxtIEF2ZSwgTGV1dmVuLCBWQlIgMzAwMCwgQmVsZ2l1bSJ9LCJnZW5kZXIiOiJmZW1hbGUiLCJuYXRpb25hbGl0eSI6WyJCRSJdLCJhZ2VPdmVyMTgiOnRydWV9LCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiaHR0cHM6Ly9hcGktcGlsb3QuZWJzaS5ldS90cnVzdGVkLXNjaGVtYXMtcmVnaXN0cnkvdjMvc2NoZW1hcy96RHBXR1VCZW5tcVh6dXJza3J5OU5zazZ2cTJSOHRoaDlWU2VvUnFndW95TUQiLCJ0eXBlIjoiRnVsbEpzb25TY2hlbWFWYWxpZGF0b3IyMDIxIn0sImV4cGlyYXRpb25EYXRlIjoiMjAzMS0xMS0zMFQwMDowMDowMFoiLCJ0ZXJtc09mVXNlIjp7ImlkIjoiaHR0cHM6Ly9hcGktcGlsb3QuZWJzaS5ldS90cnVzdGVkLWlzc3VlcnMtcmVnaXN0cnkvdjUvaXNzdWVycy9kaWQ6ZWJzaTp6eGFZYVV0Yjhwdm9BdFlOV2JLY3ZlZy9hdHRyaWJ1dGVzL2I0MGZkOWI0MDQ0MThhNDRkMmQ5OTExMzc3YTAzMTMwZGRlNDUwZWI1NDZjNzU1YjViODBhY2Q3ODI5MDJlNmQiLCJ0eXBlIjoiSXNzdWFuY2VDZXJ0aWZpY2F0ZSJ9fX0.VvcNuWj5WpoSwnDaguN-vpzTkBpPUz4KIB-AvrxS6gJ91g7N4zaJwJt3o-G05dz6IWnKQcs4-FIx7LSKtegt2w";
    const jwk = require("./fixtures/key_2.json"); // secp256k1
    const res = await client
      .get("/issue-vp")
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
          vc1,
          vc2,
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
      vc1,
      vc2,
    ]);
  });
});
