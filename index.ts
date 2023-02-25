import axios, { AxiosInstance } from "axios";
import fs from "fs";
import https from "https";
import semver from "semver";

const expectedKastelaVersion = "v0.2";
const vaultPath = "/api/vault";
const protectionPath = "/api/protection";
const securePath = "/api/secure";

type proxyCommon = {
  protections: Object;
  vaults: Object;
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
  #kastelaUrl: string;

  public constructor(
    kastelaUrl: string,
    caCertPath: string,
    clientCertPath: string,
    clientKeyPath: string
  ) {
    this.#kastelaUrl = kastelaUrl;
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

  /** Store batch vault data on the server.
   * @public
   * @param {string} vaultId
   * @param {any[]} data array of vault data
   * @return {Promise<string[]>} array of vault token
   * @example
   * // store jhon doe and jane doe data
   * client.vaultStore("yourVaultId", [{name: "jhon doe", secret : "12345678"}, {name: "jane doe", secret : "12345678"}])
   *
   */
  public async vaultStore(vaultId: string, data: any[]): Promise<string[]> {
    const { ids } = await this.#request(
      "POST",
      new URL(`${vaultPath}/${vaultId}/store`, this.#kastelaUrl),
      { data }
    );
    return ids;
  }

  /** Search vault data by indexed column.
   * @param {string} vaultId
   * @param {string} search indexed column value
   * @param {Object} params pagination parameters
   * @param {number} [params.size] pagination size
   * @param {string} [params.after] pagination offset
   * @return {Promise<string[]>}
   * @example
   * // search "jhon doe" data
   * client.vaultFetch("yourVaultId", "jhon doe", {})
   */
  public async vaultFetch(
    vaultId: string,
    search: string,
    params: { size?: number; after?: string } = {}
  ): Promise<string[]> {
    const url = new URL(`${vaultPath}/${vaultId}`, this.#kastelaUrl);
    const urlSearchParams = new URLSearchParams();
    urlSearchParams.set("search", search);
    if (params.size) {
      urlSearchParams.set("size", params.size.toString());
    }
    if (params.after) {
      urlSearchParams.set("after", params.after);
    }
    url.search = urlSearchParams.toString();
    const { ids } = await this.#request("GET", url);
    return ids;
  }

  /** Get batch vault data by vault token ids.
   * @param {string} vaultId
   * @param {string[]} ids array of vault token
   * @return {Promise<any[]>}
   * @example
   * client.VaultGet("yourVaultId", []string{"d2657324-59f3-4bd4-92b0-c7f5e5ef7269", "331787a5-8930-4167-828f-7e783aeb158c"})
   */
  public async vaultGet(vaultId: string, ids: string[]): Promise<any[]> {
    const { data } = await this.#request(
      "POST",
      new URL(`${vaultPath}/${vaultId}/get`, this.#kastelaUrl),
      { ids }
    );
    return data;
  }

  /** Update vault data by vault token.
   * @param {string} vaultId
   * @param {string[]} token vault token
   * @param {any} data update data
   * @return {Promise<void>}
   * @example
   * client.vaultUpdate("yourVaultId", "331787a5-8930-4167-828f-7e783aeb158c", {name: "jane d'arc", secret : "12345678"})
   */
  public async vaultUpdate(
    vaultId: string,
    token: string,
    data: any
  ): Promise<void> {
    await this.#request(
      "PUT",
      new URL(`${vaultPath}/${vaultId}/${token}`, this.#kastelaUrl),
      data
    );
  }

  /** Remove vault data by vault token.
   * @param {string} vaultId
   * @param {string} token vault token
   * @return {Promise<void>}
   * @example
   * //delete vault with token '331787a5-8930-4167-828f-7e783aeb158c'
   * client.vaultDelete("yourVaultId", "331787a5-8930-4167-828f-7e783aeb158c")
   */
  public async vaultDelete(vaultId: string, token: string): Promise<void> {
    await this.#request(
      "DELETE",
      new URL(`${vaultPath}/${vaultId}/${token}`, this.#kastelaUrl)
    );
  }

  /** Encrypt data protection by protection data ids, which can be used after storing data or updating data.
   * @param {string} protectionId
   * @param {any[]} ids array of protection data ids
   * @return {Promise<void>}
   * @example
   * 	// protect data with id 1,2,3,4,5
   * client.protectionSeal("yourProtectionId", [1,2,3,4,5])
   */
  public async protectionSeal(protectionId: string, ids: any[]): Promise<void> {
    await this.#request(
      "POST",
      new URL(`${protectionPath}/${protectionId}/seal`, this.#kastelaUrl),
      { ids }
    );
  }

  /** Decrypt data protection by protection data ids.
   * @param {string} protectionId
   * @param {any[]} ids array of protection data ids
   * @return {Promise<any[]>} array of decrypted data refers to ids
   * @example
   * 	// decrypt data with id 1,2,3,4,5
   * client.protectionOpen("yourProtectionId", [1,2,3,4,5])
   */
  public async protectionOpen(
    protectionId: string,
    ids: any[]
  ): Promise<any[]> {
    const { data } = await this.#request(
      "POST",
      new URL(`${protectionPath}/${protectionId}/open`, this.#kastelaUrl),
      { ids }
    );
    return data;
  }

  /** Initialize secure protection.
   * @param {string} operation secure protection operation mode
   * @param {string[]} protectionIds array of protection id
   * @param {number} ttl time to live in minutes
   * @return {Promise<{ credential: string}>} secure protection credential
   * @example
   * 	// begin secure protection
   * client.secureProtectionInit(["yourProtectionId"], 5)
   */
  public async secureProtectionInit(
    operation: "READ" | "WRITE",
    protectionIds: string[],
    ttl: number
  ): Promise<{ credential: string }> {
    const { credential } = await this.#request(
      "POST",
      new URL(`${securePath}/protection/init`, this.#kastelaUrl),
      {
        operation,
        protection_ids: protectionIds,
        ttl: ttl,
      }
    );
    return { credential };
  }

  /** Commit secure protection.
   * @param {string} credential
   * @return {Promise<void>}
   * @example
   * 	// commit secure protection
   * client.secureProtectionCommit("yourCredential")
   */
  public async secureProtectionCommit(credential: string): Promise<void> {
    await this.#request(
      "POST",
      new URL(`${securePath}/protection/commit`, this.#kastelaUrl),
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
      new URL(`/api/proxy`, this.#kastelaUrl),
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
