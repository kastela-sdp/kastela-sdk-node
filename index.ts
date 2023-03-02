import axios, { AxiosInstance } from "axios";
import fs from "fs";
import https from "https";
import semver from "semver";

const expectedKastelaVersion = "v0.2";
const vaultPath = "/api/vault";
const protectionPath = "/api/protection";
const securePath = "/api/secure";

export type vaultStoreInput = {
  vaultID: string;
  values: any[];
};

export type vaultFetchInput = {
  vaultID: string;
  search: any;
  size?: number;
  after?: string;
};

export type vaultGetInput = {
  vaultID: string;
  tokens: string[];
};

export type vaultUpdateInput = {
  vaultID: string;
  values: { token: string; value: any }[];
};

export type vaultDeleteInput = {
  vaultID: string;
  tokens: string[];
};
export type protectionSealInput = {
  protectionID: string;
  primaryKeys: any[];
};

export type protectionOpenInput = {
  protectionID: string;
  tokens: any[];
};

/**
 * @class
 * Create a new Kastela Client instance for communicating with the server.
 * Require server information and return client instance.
 * @param {string} kastelaUrl Kastela server url
 * @param {string} caCertPath Kastela ca certificate path
 * @param {string} clientCertPath Kastela client certificate path
 * @param {string} clientKeyPath kastela client key path
 */
export class Client {
  #axiosInstance: AxiosInstance;
  #kastelaURL: string;

  public constructor(
    kastelaURL: string,
    caCertPath: string,
    clientCertPath: string,
    clientKeyPath: string
  ) {
    this.#kastelaURL = kastelaURL;
    const httpsAgent = new https.Agent({
      ca: fs.readFileSync(caCertPath),
      cert: fs.readFileSync(clientCertPath),
      key: fs.readFileSync(clientKeyPath),
    });
    this.#axiosInstance = axios.create({
      httpsAgent,
    });
  }

  async #request(method: string, url: URL, body?: any) {
    try {
      const { data, headers } = await this.#axiosInstance.request({
        url: url.toString(),
        method,
        data: body,
      });
      const actualKastelaVersion = headers["x-kastela-version"]!;
      if (
        semver.satisfies(
          actualKastelaVersion,
          `${expectedKastelaVersion} || v0.0.0`
        )
      ) {
        return data;
      } else {
        throw new Error(
          `kastela server version mismatch, expected: ${expectedKastelaVersion}.x, actual: ${actualKastelaVersion}`
        );
      }
    } catch (error: any) {
      const data = error?.response?.data;
      if (data) {
        switch (typeof data) {
          case "object":
            throw new Error(data.error);
          default:
            throw new Error(data);
        }
      } else {
        throw error;
      }
    }
  }

  /** Store vault data
   * @param {Object[]} input input
   * @param {string} input[].vaultID vault id
   * @param {any[]} input[].values array of vault data
   * @return {Promise<string[][]>} array of vault token. the order of token corresponds to the order of input.
   * @example
   * const tokens = await client.vaultStore([{ vaultID: "your-vault-id", values: [{name: "alice", secret: 123 }, { name: "bob", secret: 456 }]}]);
   */
  public async vaultStore(input: vaultStoreInput[]): Promise<string[][]> {
    const { tokens } = await this.#request(
      "POST",
      new URL(`${vaultPath}/store`, this.#kastelaURL),
      input.map((v) => ({ vault_id: v.vaultID, values: v.values }))
    );
    return tokens;
  }

  /** Search vault data by indexed column.
   * @param {Object} input input
   * @param {string} input.vaultID vault id
   * @param {string} input.search indexed column value
   * @param {number} [input.size] pagination limit
   * @param {number} [input.after] pagination after
   * @return {Promise<string[]>}
   * @example
   * const tokens = await client.vaultFetch({ vaultID: "your-vault-id", search: "bob", size: 10, after: "token" })
   */
  public async vaultFetch(input: vaultFetchInput): Promise<string[]> {
    const body: {
      vault_id: string;
      search: any;
      size?: number;
      after?: string;
    } = {
      vault_id: input.vaultID,
      search: input.search,
    };
    if (input.size) {
      body.size = input.size;
    }
    if (input.after?.length) {
      body.after = input.after;
    }
    const { tokens } = await this.#request(
      "POST",
      new URL(`${vaultPath}/fetch`, this.#kastelaURL),
      body
    );
    return tokens;
  }

  /** Get vault data
   * @param {Object[]} input
   * @param {string} input[].vaultID vault id
   * @param {string[]} input[].tokens array of tokens
   * @return {Promise<any[][]>}
   * @example
   * const values = await client.VaultGet([{ vaultID: "your-vault-id", tokens: ["a", "b", "c", "d", "e"]}]);
   */
  public async vaultGet(input: vaultGetInput[]): Promise<any[][]> {
    const { values } = await this.#request(
      "POST",
      new URL(`${vaultPath}/get`, this.#kastelaURL),
      input.map((v) => ({ vault_id: v.vaultID, tokens: v.tokens }))
    );
    return values;
  }

  /** Update vault data
   * @param {Object[]} input
   * @param {string} input[].vaultID vault id
   * @param {Object[]} input[].values array of values
   * @param {string} input[].values[].token token
   * @param {any} input[].values[].value value
   * @return {Promise<void>}
   * @example
   * await client.vaultUpdate([{ vaultID: "your-vault-id", values: [{ token: "c", value: { name: "carol", secret: 789 }}]}])
   */
  public async vaultUpdate(input: vaultUpdateInput[]): Promise<void> {
    await this.#request(
      "POST",
      new URL(`${vaultPath}/update`, this.#kastelaURL),
      input.map((v) => ({ vault_id: v.vaultID, values: v.values }))
    );
  }

  /** Delete vault data
   * @param {Object[]} input
   * @param {string} input[].vaultID vault id
   * @param {string[]} input[].tokens array of tokens
   * @return {Promise<any[][]>}
   * @example
   * await client.vaultDelete([{ vaultID: "your-vault-id", tokens: ["d", "e"]}])
   */
  public async vaultDelete(input: vaultDeleteInput[]): Promise<void> {
    await this.#request(
      "POST",
      new URL(`${vaultPath}/delete`, this.#kastelaURL),
      input.map((v) => ({ vault_id: v.vaultID, tokens: v.tokens }))
    );
  }

  /** Encrypt protection data
   * @param {Object[]} input protection seal input data
   * @param {string} input[].protectionID protection id
   * @param {any[]} input[].primaryKeys array of data primary keys
   * @return {Promise<void>}
   * @example
   * await client.protectionSeal([{ protectionID: "your-protection-id", primaryKeys: [1, 2, 3, 4, 5]}])
   */
  public async protectionSeal(input: protectionSealInput[]): Promise<void> {
    await this.#request(
      "POST",
      new URL(`${protectionPath}/seal`, this.#kastelaURL),
      input.map((v) => ({
        protection_id: v.protectionID,
        primary_keys: v.primaryKeys,
      }))
    );
  }

  /** Decrypt protection data
   * @param {Object[]} input protection open input data
   * @param {string} input[].protectionID protection id
   * @param {any[]} input[].tokens array of tokens
   * @return {Promise<any[][]>} array of decrypted data. the order of data corresponds to the order of input.
   * @example
   * const data = await client.protectionOpen({ protectionID: "your-protection-id" ,tokens: ["a", "b", "c", "d", "e"]})
   */
  public async protectionOpen(input: protectionOpenInput[]): Promise<any[][]> {
    const { data } = await this.#request(
      "POST",
      new URL(`${protectionPath}/open`, this.#kastelaURL),
      input.map((v) => ({
        protection_id: v.protectionID,
        tokens: v.tokens,
      }))
    );
    return data;
  }

  /** Initialize secure protection.
   * @param {string} operation secure protection operation mode
   * @param {string[]} protectionIDs array of protection id
   * @param {number} ttl time to live in minutes
   * @return {Promise<{ credential: string}>} secure protection credential
   * @example
   * const { credential } = await client.secureProtectionInit(["your-protection-id"], 5)
   */
  public async secureProtectionInit(
    operation: "READ" | "WRITE",
    protectionIDs: string[],
    ttl: number
  ): Promise<{ credential: string }> {
    const { credential } = await this.#request(
      "POST",
      new URL(`${securePath}/protection/init`, this.#kastelaURL),
      {
        operation,
        protection_ids: protectionIDs,
        ttl: ttl,
      }
    );
    return { credential };
  }

  /** Commit secure protection.
   * @param {string} credential
   * @return {Promise<void>}
   * @example
   * await client.secureProtectionCommit("your-credential")
   */
  public async secureProtectionCommit(credential: string): Promise<void> {
    await this.#request(
      "POST",
      new URL(`${securePath}/protection/commit`, this.#kastelaURL),
      { credential }
    );
  }

  /**
   *  proxying your request.
   * @param {"json"|"xml"} type request body type
   * @param {string} url request url
   * @param {"get"|"post"} param.method request method
   * @param {object} [common] needed information for protection and vault.
   * @param {object} [common.vaults] vaults object list. Define column with prefix as key and array with id as first index and vault column as second index.
   * @param {object} [common.protections] protections object list. Define column with prefix as key and protectionId as value.
   * @param {object} [options.headers] request headers, use "_" prefix for encrypted column key and data id/token as value.
   * @param {object} [options.params] request parameters, use "_" prefix for encrypted column key and data id/token as value.
   * @param {object} [options.body] request body, use "_" prefix for encrypted column key and data id/token as value.
   * @param {object} [options.query] request query, use "_" prefix for encrypted column key and data id/token as value.
   * @param {string} [options.rootTag] root tag, required for xml type
   * @return {Promise<any>}
   * @example
   *client.privacyProxyRequest(
      "json",
      "https://enskbwhbhec7l.x.pipedream.net/:_phone/:_salary",
      "post",
      {
        protections: {
          _email: "124edec8-530e-4fd2-a04b-d4dc21ce625a", // email protection id
          _phone: "9f53aa3b-7214-436d-af9b-d2952be9f0c4", // phone protection id
        },
        vaults: {
          _salary: ["c5f9236d-aea0-46a5-a2fe-fb75c0596c87", "salary"], // salary vault id & column
        },
      },
      {
        headers: {
          _email: "1", // email data id
        },
        params: {
          _phone: "1", // email data id
          _salary: "01GQEATT1Q3NKKDC3A2JSMN7ZJ", // salary vault token
        },
        body: {
          name: "jhon daeng",
          _email: "1", // email data id
          _phone: "1", // phone data id
          _salary: "01GQEATT1Q3NKKDC3A2JSMN7ZJ", salary vault token
        },
        query: {
          id: "123456789",
          _email: "1",
        },
      }
    );
   */
  public async privacyProxyRequest(
    type: "json" | "xml",
    url: string,
    method: "get" | "post" | "put" | "delete" | "patch",
    common: {
      protections: object;
      vaults: object;
    } = { protections: {}, vaults: {} },
    options: {
      headers?: object;
      params?: object;
      body?: object;
      query?: object;
      rootTag?: string;
    } = {}
  ) {
    if (type === "xml" && !options.rootTag) {
      throw new Error("rootTag is required for xml");
    }
    const data = await this.#request(
      "POST",
      new URL(`/api/proxy`, this.#kastelaURL),
      {
        type,
        url,
        method,
        common,
        options,
      }
    );
    return data;
  }
}
