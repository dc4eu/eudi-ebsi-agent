const express = require("express");
const path = require("path");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/", (req, res) => {
  res.send("Service is up")
});

const hostname = "0.0.0.0";
const port = process.env.PORT || 3000;

app.listen(port, hostname, () => {
  console.log(`Server listening at port: ${port}`)
})
