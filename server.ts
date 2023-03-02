import {
  Client,
  vaultStoreInput,
  vaultGetInput,
  vaultUpdateInput,
  vaultDeleteInput,
  vaultFetchInput,
} from "./index";
import express, { NextFunction, Request, Response } from "express";

const client = new Client(
  "https://127.0.0.1:3100",
  "./credentials/ca.crt",
  "./credentials/client.crt",
  "./credentials/client.key"
);

const app = express();
app.use(express.json({ limit: 4 * 1024 * 1024 }));

app.post("/api/vault/store", async (req, res, next) => {
  try {
    const input: vaultStoreInput[] = req.body.map(
      (storeInput: { vault_id: string; values: string[] }) => ({
        vaultID: storeInput.vault_id,
        values: storeInput.values,
      })
    );
    const ids = await client.vaultStore(input);
    res.send(ids);
  } catch (error) {
    next(error);
  }
});

app.post("/api/vault/fetch", async (req, res, next) => {
  try {
    const input: vaultFetchInput = {
      vaultID: req.body.vault_id,
      search: req.body.search,
    };
    if (req.body.size) {
      input.size = req.body.size;
    }
    if (req.body.after?.length) {
      input.after = req.body.after;
    }
    const tokens = await client.vaultFetch(input);
    res.json(tokens);
  } catch (error) {
    next(error);
  }
});

app.post("/api/vault/get", async (req, res, next) => {
  try {
    const input: vaultGetInput[] = req.body.map(
      (getInput: { vault_id: string; tokens: string[] }) => ({
        vaultID: getInput.vault_id,
        tokens: getInput.tokens,
      })
    );
    const values = await client.vaultGet(input);
    res.json(values);
  } catch (error) {
    next(error);
  }
});

app.post("/api/vault/update", async (req, res, next) => {
  try {
    const input: vaultUpdateInput[] = req.body.map(
      (updateInput: {
        vault_id: string;
        values: { token: string; value: any }[];
      }) => ({
        vaultID: updateInput.vault_id,
        values: updateInput.values,
      })
    );
    await client.vaultUpdate(input);
    res.send("OK");
  } catch (error) {
    next(error);
  }
});

app.post("/api/vault/delete", async (req, res, next) => {
  try {
    const input: vaultDeleteInput[] = req.body.map(
      (getInput: { vault_id: string; tokens: string[] }) => ({
        vaultID: getInput.vault_id,
        tokens: getInput.tokens,
      })
    );
    await client.vaultDelete(input);
    res.send("OK");
  } catch (error) {
    next(error);
  }
});

app.post("/api/protection/seal", async (req, res, next) => {
  try {
    await client.protectionSeal(req.body);
    res.send("OK");
  } catch (error) {
    next(error);
  }
});

app.post("/api/protection/open", async (req, res, next) => {
  try {
    const data = await client.protectionOpen(req.body);
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
