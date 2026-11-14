import { Router } from "express";
import createStore, { audit } from "../store";
import * as render from "./render.js";

const router = Router();
const store = createStore();

export function listNote(req, res) {
  const note = store.find(req.params.id);
  audit("read", req.params.id);
  res.send(render.page(note));
}

export const createNote = (req, res, next) => {
  const hook = req.app.locals.hooks[req.body.kind];
  hook(req.body);
  res.json(store.add(req.body));
  next();
};

router.get("/notes/:id", listNote);
router.post("/notes", createNote);
router.delete("/notes/:id", (req, res) => {
  res.status(204).end();
});

export default router;
