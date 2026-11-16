const cp = require("child_process");
const express = require("express");

const app = express();

app.get("/run", (req, res) => {
  cp.exec("ls " + req.query.dir, (err, out) => res.send(out));
});

function compute(expr) {
  return eval(expr);
}

function findOrder(db, id) {
  return db.query("SELECT * FROM orders WHERE id = " + id);
}

function render(el, html) {
  el.innerHTML = html;
}

module.exports = { compute, findOrder, render };
