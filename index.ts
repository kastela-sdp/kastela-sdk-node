import axios, { AxiosInstance } from "axios";
import fs from "fs";
import https from "https";
import semver from "semver";

const expectedKastelaVersion = "v0.0";
const vaultPath = "/api/vault";
const protectionPath = "/api/protection";

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

  public vault = {
    store: async (vaultId: string, data: any[]): Promise<string[]> => {
      const { ids } = await this.#request(
        "POST",
        new URL(`${vaultPath}/${vaultId}/store`, this.#kastelaUrl),
        { data }
      );
      return ids;
    },

    fetch: async (
      vaultId: string,
      search: string,
      params: { size?: number; after?: string } = {}
    ): Promise<string[]> => {
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
    },

    get: async (vaultId: string, ids: string[]): Promise<any[]> => {
      const { data } = await this.#request(
        "POST",
        new URL(`${vaultPath}/${vaultId}/get`, this.#kastelaUrl),
        { ids }
      );
      return data;
    },

    update: async (
      vaultId: string,
      token: string,
      data: any
    ): Promise<void> => {
      await this.#request(
        "PUT",
        new URL(`${vaultPath}/${vaultId}/${token}`, this.#kastelaUrl),
        data
      );
    },

    delete: async (vaultId: string, token: string): Promise<void> => {
      await this.#request(
        "DELETE",
        new URL(`${vaultPath}/${vaultId}/${token}`, this.#kastelaUrl)
      );
    },
  };

  public protection = {
    seal: async (protectionId: string, ids: any[]): Promise<void> => {
      await this.#request(
        "POST",
        new URL(`${protectionPath}/${protectionId}/seal`, this.#kastelaUrl),
        { ids }
      );
    },

    open: async (protectionId: string, ids: any[]): Promise<any[]> => {
      const { data } = await this.#request(
        "POST",
        new URL(`${protectionPath}/${protectionId}/open`, this.#kastelaUrl),
        { ids }
      );
      return data;
    },
  };
}
