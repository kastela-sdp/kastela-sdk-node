import axios, { AxiosInstance } from "axios";
import fs from "fs";
import https from "https";
import semver from "semver";

const expectedKastelaVersion = "v0.0";
const vaultPath = "/api/vault";
const protectionPath = "/api/protection";

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
}
