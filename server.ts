import { Client } from "./index";
import express, { NextFunction, Request, Response } from "express";

const client = new Client(
  "https://127.0.0.1:8080",
  "./ca.crt",
  "./client.crt",
  "./client.key"
);

const app = express();
app.use(express.json());

app.post("/vault/:vaultId/store", async (req, res, next) => {
  try {
    const ids = await client.vault.store(req.params.vaultId, req.body);
    res.send(ids);
  } catch (error) {
    next(error);
  }
});

app.get("/vault/:vaultId", async (req, res, next) => {
  try {
    if (!req.query.search) {
      throw new Error("search not found in query parameter");
    }
    const ids = await client.vault.fetch(
      req.params.vaultId,
      req.query.search.toString(),
      {
        size: Number.parseInt(req.query.size?.toString() || "0"),
        after: req.query.after?.toString(),
      }
    );
    res.json(ids);
  } catch (error) {
    next(error);
  }
});

app.post("/vault/:vaultId/get", async (req, res, next) => {
  try {
    const data = await client.vault.get(req.params.vaultId, req.body);
    res.json(data);
  } catch (error) {
    next(error);
  }
});

app.put("/vault/:vaultId/:token", async (req, res, next) => {
  try {
    await client.vault.update(req.params.vaultId, req.params.token, req.body);
    res.send("OK");
  } catch (error) {
    next(error);
  }
});

app.delete("/vault/:vaultId/:token", async (req, res, next) => {
  try {
    await client.vault.delete(req.params.vaultId, req.params.token);
    res.send("OK");
  } catch (error) {
    next(error);
  }
});

app.post("/protection/:protectionId/seal", async (req, res, next) => {
  try {
    await client.protection.seal(req.params.protectionId, req.body);
    res.send("OK");
  } catch (error) {
    next(error);
  }
});

app.post("/protection/:protectionId/open", async (req, res, next) => {
  try {
    const data = await client.protection.open(
      req.params.protectionId,
      req.body
    );
    res.json(data);
  } catch (error) {
    next(error);
  }
});

app.use(async (err: any, req: Request, res: Response, next: NextFunction) => {
  res.status(500).send(err.message);
});

const port = 4000;
app.listen(port, () => {
  console.log(`listening on port ${port}`);
});
