import axios, { AxiosInstance } from "axios";
import https from "https";

const cryptoPath = "/api/crypto";
const vaultPath = "/api/vault";
const protectionPath = "/api/protection";
const securePath = "/api/secure";

export type EncryptionMode =
  | "AES_GCM"
  | "CHACHA20_POLY1305"
  | "XCHACHA20_POLY1305"
  | "RSA_OAEP";

export type HashMode =
  | "BLAKE2B_256"
  | "BLAKE2B_512"
  | "BLAKE2S_256"
  | "BLAKE3_256"
  | "BLAKE3_512"
  | "SHA256"
  | "SHA512"
  | "SHA3_256"
  | "SHA3_512";

export interface CryptoEncryptInput {
  keyID: string;
  mode: EncryptionMode;
  plaintexts: any[];
}

export interface CryptoHMACInput {
  keyID: string;
  mode: HashMode;
  values: any[];
}

export interface CryptoEqualInput {
  hash: string;
  value: any;
}

export interface CryptoSignInput {
  keyID: string;
  values: any[];
}

export interface CryptoVerifyInput {
  signature: string;
  value: any;
}

export interface VaultStoreInput {
  vaultID: string;
  values: any[];
}

export interface VaultFetchInput {
  vaultID: string;
  search: any;
  size?: number;
  after?: string;
}

export interface VaultCountInput {
  vaultID: string;
  search: any;
}

export interface VaultGetInput {
  vaultID: string;
  tokens: string[];
}

export interface VaultUpdateInput {
  vaultID: string;
  values: { token: string; value: any }[];
}

export interface VaultDeleteInput {
  vaultID: string;
  tokens: string[];
}

export interface ProtectionTokenizeInput {
  protectionID: string;
  values: any[];
}

export interface ProtectionSealInput {
  protectionID: string;
  primaryKeys: any[];
}

export interface ProtectionOpenInput {
  protectionID: string;
  tokens: any[];
}

export interface ProtectionFetchInput {
  protectionID: string;
  search: any;
}

export interface ProtectionCountInput {
  protectionID: string;
  search: any;
}

/**
 * @class
 * Create a new Kastela Client instance for communicating with the server.
 * Require server information and return client instance.
 * @param {string} kastelaUrl Kastela server url
 * @param {string} caCert Kastela ca certificate
 * @param {string} clientCert Kastela client certificate
 * @param {string} clientKey kastela client key
 */
export class Client {
  #axiosInstance: AxiosInstance;
  #kastelaURL: string;

  public constructor(
    kastelaURL: string,
    caCert: Buffer,
    clientCert: Buffer,
    clientKey: Buffer
  ) {
    this.#kastelaURL = kastelaURL;
    const httpsAgent = new https.Agent({
      ca: caCert,
      cert: clientCert,
      key: clientKey,
    });
    this.#axiosInstance = axios.create({
      httpsAgent,
    });
  }

  async #request(method: string, url: URL, body?: any) {
    try {
      const { data } = await this.#axiosInstance.request({
        url: url.toString(),
        method,
        data: body,
      });
      return data;
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

  /** Encrypt data
   * @param {Object[]} input input
   * @param {string} input[].keyID key id
   * @param {string} input[].mode encryption mode
   * @param {any[]} input[].plaintexts array of plaintexts
   * @return {Promise<string[][]>} array of ciphertext. the order of ciphertext corresponds to the order of input
   * @example
   * const ciphertexts = await client.cryptoEncrypt([{keyID: "your-key-id", mode: "AES_GCM", plaintexts: ["foo", "bar"]}]);
   */
  public async cryptoEncrypt(input: CryptoEncryptInput[]): Promise<string[][]> {
    const { ciphertexts } = await this.#request(
      "POST",
      new URL(`${cryptoPath}/encrypt`, this.#kastelaURL),
      input.map((v) => ({
        key_id: v.keyID,
        mode: v.mode,
        plaintexts: v.plaintexts,
      }))
    );
    return ciphertexts;
  }

  /** Decrypt data
   * @param {string[]} input array of ciphertext
   * @return {Promise<any[]>} array of plaintext. the order of plaintext corresponds to the order of ciphertext
   * @example
   * const plaintexts = await client.cryptoDecrypt(["foo", "bar"]);
   */
  public async cryptoDecrypt(input: string[]): Promise<any[]> {
    const { plaintexts } = await this.#request(
      "POST",
      new URL(`${cryptoPath}/decrypt`, this.#kastelaURL),
      input
    );
    return plaintexts;
  }

  /** HMAC data
   * @param {Object[]} input input
   * @param {string} input[].keyID key id
   * @param {string} input[].mode hash mode
   * @param {any[]} input[].values array of value
   * @return {Promise<string[][]>} array of hash. the order of hash corresponds to the order of input
   * @example
   * const hashes = await client.cryptoHMAC([{keyID: "your-key-id", mode: "SHA256", values: ["foo", "bar"]}]);
   */
  public async cryptoHMAC(input: CryptoHMACInput[]): Promise<string[][]> {
    const { hashes } = await this.#request(
      "POST",
      new URL(`${cryptoPath}/hmac`, this.#kastelaURL),
      input.map((v) => ({
        key_id: v.keyID,
        mode: v.mode,
        values: v.values,
      }))
    );
    return hashes;
  }

  /** Compare hash and data
   * @param {Object[]} input input
   * @param {string} input[].hash hash
   * @param {any} input[].value value
   * @return {Promise<boolean[]>} array of result. the order of result corresponds to the order of input
   * @example
   * const result = await client.cryptoEqual([{hash: "foo", value: 123}, {hash: "bar", value: 456}]);
   */
  public async cryptoEqual(input: CryptoEqualInput[]): Promise<boolean[]> {
    const { result } = await this.#request(
      "POST",
      new URL(`${cryptoPath}/equal`, this.#kastelaURL),
      input
    );
    return result;
  }

  /** Sign data
   * @param {Object[]} input input
   * @param {string} input[].keyID key id
   * @param {any[]} input[].values array of value
   * @return {Promise<string[][]>} array of signature. the order of signature corresponds to the order of input
   * @example
   * const signatures = await client.cryptoSign([{keyID: "your-key-id", values: ["foo", "bar"]}]);
   */
  public async cryptoSign(input: CryptoSignInput[]): Promise<string[][]> {
    const { signatures } = await this.#request(
      "POST",
      new URL(`${cryptoPath}/sign`, this.#kastelaURL),
      input.map((v) => ({ key_id: v.keyID, values: v.values }))
    );
    return signatures;
  }

  /** Verify data signature
   * @param {Object[]} input input
   * @param {string} input[].signature hash
   * @param {any} input[].value value
   * @return {Promise<boolean[]>} array of result. the order of result corresponds to the order of input
   * @example
   * const result = await client.cryptoVerify([{signature: "foo", value: 123}, {signature: "bar", value: 456}]);
   */
  public async cryptoVerify(input: CryptoVerifyInput[]): Promise<boolean[]> {
    const { result } = await this.#request(
      "POST",
      new URL(`${cryptoPath}/verify`, this.#kastelaURL),
      input
    );
    return result;
  }

  /** Store vault data
   * @param {Object[]} input input
   * @param {string} input[].vaultID vault id
   * @param {any[]} input[].values array of vault data
   * @return {Promise<string[][]>} array of vault token. the order of token corresponds to the order of input
   * @example
   * const tokens = await client.vaultStore([{vaultID: "your-vault-id", values: ["foo", "bar"]}]);
   */
  public async vaultStore(input: VaultStoreInput[]): Promise<string[][]> {
    const { tokens } = await this.#request(
      "POST",
      new URL(`${vaultPath}/store`, this.#kastelaURL),
      input.map((v) => ({ vault_id: v.vaultID, values: v.values }))
    );
    return tokens;
  }

  /** Search vault data
   * @param {Object} input input
   * @param {string} input.vaultID vault id
   * @param {string} input.search data to search
   * @return {Promise<string[]>}
   * @example
   * const tokens = await client.vaultFetch({vaultID: "your-vault-id", search: "foo", size: 10, after: "bar"})
   */
  public async vaultFetch(input: VaultFetchInput): Promise<string[]> {
    const body: {
      vault_id: string;
      search: any;
      size?: number;
      after?: string;
    } = { vault_id: input.vaultID, search: input.search };
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

  /** Count vault data
   * @param {Object} input input
   * @param {string} input.vaultID vault id
   * @param {string} input.search data to search
   * @return {Promise<string[]>}
   * @example
   * const count = await client.vaultCount({vaultID: "your-vault-id", search: "foo"})
   */
  public async vaultCount(input: VaultCountInput): Promise<number> {
    const body: { vault_id: string; search: any } = {
      vault_id: input.vaultID,
      search: input.search,
    };
    const { count } = await this.#request(
      "POST",
      new URL(`${vaultPath}/count`, this.#kastelaURL),
      body
    );
    return count;
  }

  /** Get vault data
   * @param {Object[]} input
   * @param {string} input[].vaultID vault id
   * @param {string[]} input[].tokens array of token
   * @return {Promise<any[][]>} array of value, the order of value corresponds to the order of token
   * @example
   * const values = await client.VaultGet([{vaultID: "your-vault-id", tokens: ["foo", "bar", "baz"]}]);
   */
  public async vaultGet(input: VaultGetInput[]): Promise<any[][]> {
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
   * await client.vaultUpdate([{vaultID: "your-vault-id", values: [{ token: "foo", value: "bar"}]}])
   */
  public async vaultUpdate(input: VaultUpdateInput[]): Promise<void> {
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
   * @return {Promise<void>}
   * @example
   * await client.vaultDelete([{ vaultID: "your-vault-id", tokens: ["foo", "bar"]}])
   */
  public async vaultDelete(input: VaultDeleteInput[]): Promise<void> {
    await this.#request(
      "POST",
      new URL(`${vaultPath}/delete`, this.#kastelaURL),
      input.map((v) => ({ vault_id: v.vaultID, tokens: v.tokens }))
    );
  }

  /** Tokenize data for protection
   * @param {Object[]} input protection tokenize input data
   * @param {string} input[].protectionID protection id
   * @param {any[]} input[].values array of data
   * @return {Promise<void>}
   * @example
   * const tokens = await client.protectionTokenize([{ protectionID: "your-protection-id", values: ["foo", "bar", "baz"]}])
   */
  public async protectionTokenize(
    input: ProtectionTokenizeInput[]
  ): Promise<any[]> {
    const { tokens } = await this.#request(
      "POST",
      new URL(`${protectionPath}/tokenize`, this.#kastelaURL),
      input.map((v) => ({
        protection_id: v.protectionID,
        values: v.values,
      }))
    );
    return tokens;
  }

  /** Encrypt protection data
   * @param {Object[]} input protection seal input data
   * @param {string} input[].protectionID protection id
   * @param {any[]} input[].primaryKeys array of data primary keys
   * @return {Promise<void>}
   * @example
   * await client.protectionSeal([{ protectionID: "your-protection-id", primaryKeys: [1, 2, 3]}])
   */
  public async protectionSeal(input: ProtectionSealInput[]): Promise<void> {
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
   * @return {Promise<any[][]>} array of decrypted data. the order of values corresponds to the order of input.
   * @example
   * const data = await client.protectionOpen([{ protectionID: "your-protection-id", tokens: ["foo", "bar", "baz"]}])
   */
  public async protectionOpen(input: ProtectionOpenInput[]): Promise<any[][]> {
    const { values } = await this.#request(
      "POST",
      new URL(`${protectionPath}/open`, this.#kastelaURL),
      input.map((v) => ({ protection_id: v.protectionID, tokens: v.tokens }))
    );
    return values;
  }

  /** Fetch protection data
   * @param {Object} input protection fetch input data
   * @param {string} input.protectionID protection id
   * @param {any} input.search data to search
   * @return {Promise<any[]>} array of primary keys
   * @example
   * const primaryKeys = await client.protectionFetch({ protectionID: "your-protection-id", search: "foo"})
   */
  public async protectionFetch(input: ProtectionFetchInput): Promise<any[]> {
    const { primary_keys } = await this.#request(
      "POST",
      new URL(`${protectionPath}/fetch`, this.#kastelaURL),
      { protection_id: input.protectionID, search: input.search }
    );
    return primary_keys;
  }

  /** Count protection data
   * @param {Object} input protection count input data
   * @param {string} input.protectionID protection id
   * @param {any} input.search data to search
   * @return {Promise<number>} count of data
   * @example
   * const count = await client.protectionCount({ protectionID: "your-protection-id", search: "foo"})
   */
  public async protectionCount(input: ProtectionCountInput): Promise<any[]> {
    const { count } = await this.#request(
      "POST",
      new URL(`${protectionPath}/count`, this.#kastelaURL),
      { protection_id: input.protectionID, search: input.search }
    );
    return count;
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

  /** Initialize secure vault.
   * @param {string} operation secure vault operation mode
   * @param {string[]} vaultIDs array of vault id
   * @param {number} ttl time to live in minutes
   * @return {Promise<{ credential: string}>} secure vault credential
   * @example
   * const { credential } = await client.secureVaultInit(["your-vault-id"], 5)
   */
  public async secureVaultInit(
    operation: "READ" | "WRITE",
    vaultIDs: string[],
    ttl: number
  ): Promise<{ credential: string }> {
    const { credential } = await this.#request(
      "POST",
      new URL(`${securePath}/vault/init`, this.#kastelaURL),
      {
        operation,
        vault_ids: vaultIDs,
        ttl: ttl,
      }
    );
    return { credential };
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
