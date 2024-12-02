const express = require("express");
const path = require("path");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const hostname = "0.0.0.0";
const port = process.env.PORT || 1337;

app.get("/", (req, res) => {
  res.send("Service is up")
});

app.get("/info", (req, res) => {
  res.json({
    "name": "EBSI Ledger Onboarding Service"
  });
});

app.listen(port, hostname, () => {
  console.log(`Server listening at port: ${port}`)
})

module.exports = app;
