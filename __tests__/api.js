const server = require("../app/server");
const supertest = require("supertest");
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
