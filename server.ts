import { Client } from "./index";
import express, { NextFunction, Request, Response } from "express";

const client = new Client(
  "https://127.0.0.1:3100",
  "./credentials/ca.crt",
  "./credentials/client.crt",
  "./credentials/client.key"
);

const app = express();
app.use(express.json());

app.post("/api/vault/:vaultId/store", async (req, res, next) => {
  try {
    const ids = await client.vaultStore(req.params.vaultId, req.body);
    res.send(ids);
  } catch (error) {
    next(error);
  }
});

app.get("/api/vault/:vaultId", async (req, res, next) => {
  try {
    if (!req.query.search) {
      throw new Error("search not found in query parameter");
    }
    const ids = await client.vaultFetch(
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

app.post("/api/vault/:vaultId/get", async (req, res, next) => {
  try {
    const data = await client.vaultGet(req.params.vaultId, req.body);
    res.json(data);
  } catch (error) {
    next(error);
  }
});

app.put("/api/vault/:vaultId/:token", async (req, res, next) => {
  try {
    await client.vaultUpdate(req.params.vaultId, req.params.token, req.body);
    res.send("OK");
  } catch (error) {
    next(error);
  }
});

app.delete("/api/vault/:vaultId/:token", async (req, res, next) => {
  try {
    await client.vaultDelete(req.params.vaultId, req.params.token);
    res.send("OK");
  } catch (error) {
    next(error);
  }
});

app.post("/api/protection/:protectionId/seal", async (req, res, next) => {
  try {
    await client.protectionSeal(req.params.protectionId, req.body);
    res.send("OK");
  } catch (error) {
    next(error);
  }
});

app.post("/api/protection/:protectionId/open", async (req, res, next) => {
  try {
    const data = await client.protectionOpen(req.params.protectionId, req.body);
    res.json(data);
  } catch (error) {
    next(error);
  }
});

app.post("/api/secure/protection/init", async (req, res, next) => {
  try {
    const data = await client.secureProtectionInit(
      req.body.operation,
      req.body.protection_ids,
      req.body.ttl
    );
    res.json(data);
  } catch (error) {
    next(error);
  }
});

app.post("/proxy", async (req, res, next) => {
  try {
    const { type, url, method, common, options } = req.body;
    const data = await client.privacyProxyRequest(
      type,
      url,
      method,
      common,
      options
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
