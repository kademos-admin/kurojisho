const express = require("express");
const notes = require("./routes/notes");

const app = express();
app.use(notes.default);

function start(port) {
  app.listen(port);
}

start(3000);
module.exports = { start };
