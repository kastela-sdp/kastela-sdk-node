import axios, { AxiosInstance } from "axios";
import fs from "fs";
import https from "https";
import semver from "semver";

const expectedKastelaVersion = "v0.0";
const vaultPath = "/api/vault";
const protectionPath = "/api/protection";

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

  /**
   *  proxying your request.
   * @param {Object} param
   * @param {"json"|"xml"} param.type request body type
   * @param {string} param.url request url
   * @param {"get"|"post"} param.method request method
   * @param {any} [param.headers] request headers, use "_" prefix for encrypted column key and data id/token as value.
   * @param {any} [param.params] request parameters, use "_" prefix for encrypted column key and data id/token as value.
   * @param {any} [param.body] request body, use "_" prefix for encrypted column key and data id/token as value.
   * @param {any} [param.query] request query, use "_" prefix for encrypted column key and data id/token as value.
   * @param {Object} [param.common] needed information for protection and vault.
   * @param {Object} [param.common.protections] protections object list. Define column with prefix as key and protectionId as value.
   * @param {Object} [param.common.vaults] vaults object list. Define column with prefix as key and array with id as first index and vault column as second index.
   * @param {any} [param.rootTag]
   * @return {Promise<any>}
   * @example
   * client.privacyProxy({
      type: "xml",
      rootTag: "data",
      url: "https://enskbwhbhec7l.x.pipedream.net/:_phone/:_salary",
      method: "post",
      headers: {
        _email: "1",
      },
      params: {
        _phone: "1",
        _salary: "01GQEATT1Q3NKKDC3A2JSMN7ZJ",
      },
      body: {
        name: "jhon daeng",
        _email: "1",
        _phone: "1",
        _salary: "01GQEATT1Q3NKKDC3A2JSMN7ZJ",
      },
      query: {
        id: "123456789",
        _email: "1",
      },
      common: {
        protections: {
          _email: "124edec8-530e-4fd2-a04b-d4dc21ce625a",
          _phone: "9f53aa3b-7214-436d-af9b-d2952be9f0c4",
        },
        vaults: {
          _salary: ["c5f9236d-aea0-46a5-a2fe-fb75c0596c87", "salary"],
        },
      },
    })
   */
  public async privacyProxy({
    type,
    url,
    method,
    headers,
    params,
    body,
    query,
    common,
    rootTag,
  }: {
    type: "json" | "xml";
    url: string;
    method: "get" | "post";
    common: any;
    headers?: any;
    params?: any;
    body?: any;
    query?: any;
    rootTag?: string;
  }) {
    if (type === "xml" && !rootTag) {
      throw new Error("rootTag is required for xml");
    }
    const data = await this.#request(
      "POST",
      new URL(`/api/proxy`, this.#kastelaUrl),
      {
        type,
        url,
        method,
        headers,
        params,
        body,
        query,
        common,
        rootTag,
      }
    );
    return data;
  }
}
