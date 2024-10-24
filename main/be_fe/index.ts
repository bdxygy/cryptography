import {
  publicDecrypt as publicDecryptBrowser,
  randomBytes,
} from "crypto-browserify";
import { createDecipheriv as createDecipherIvBrowser } from "browserify-aes";
import { str } from "../../message";
import { readFileSync, writeFileSync } from "node:fs";
import { privateKey } from "../../certs/private";
import { publicKey } from "../../certs/public";
import {
  createCipheriv as createDecipherIvNode,
  privateEncrypt as privateEncryptNode,
} from "node:crypto";
import { encoding, delimiter } from "../../utils";

const createAesChiperNode = (key: any, iv: string) =>
  createDecipherIvNode("aes-256-gcm", key, Buffer.from(iv, encoding));

const createAesDechiperBrowser = (key: any, iv: string) =>
  createDecipherIvBrowser("aes-256-gcm", key, Buffer.from(iv, encoding));

// Generate AES key and IV
const aesKey = randomBytes(32); // AES-256 key
const ivKey = randomBytes(12).toString(encoding); // Initialization vector for GCM (12 bytes for GCM)

// Encrypt large message with AES-GCM
const backChiper = createAesChiperNode(aesKey, ivKey);
let encryptedMessage = backChiper.update(str, "utf8", encoding);
encryptedMessage += backChiper.final(encoding);
const authTag = backChiper.getAuthTag().toString(encoding); // Get the authentication tag

// Encrypt AES key with RSA
const encryptedAesKey = privateEncryptNode(privateKey, aesKey).toString(
  encoding
);

const snapshot = {
  data: encryptedMessage,
  session: `${ivKey}${delimiter}${authTag}${delimiter}${encryptedAesKey}`,
};

// Send into Backend
writeFileSync("snapshot/2.be.payload.snapshot.json", JSON.stringify(snapshot));

/**
 *
 * This is a separate script to decrypt the response.
 *
 */

// Receive from Backend
const payloadSnapshot = JSON.parse(
  readFileSync("snapshot/2.be.payload.snapshot.json", "utf8")
);

const extractResponse = (response: typeof snapshot) => {
  const { data, session } = response;
  const [iv, auth, key] = session.split(delimiter);

  return {
    data,
    iv,
    auth,
    key,
  };
};

const {
  data: dataJson,
  iv: IvJson,
  auth: authJson,
  key: keyJson,
} = extractResponse(payloadSnapshot);

// Decrypt AES key with RSA
const decryptedAesKey = publicDecryptBrowser(
  publicKey,
  Buffer.from(keyJson, encoding)
);

const frontDechiper = createAesDechiperBrowser(decryptedAesKey, IvJson);

// Decrypt message with AES-GCM
frontDechiper.setAuthTag(Buffer.from(authJson, encoding)); // Set the authentication tag
let decryptedMessage = frontDechiper.update(dataJson, encoding, "utf8");
decryptedMessage += frontDechiper.final("utf8");

writeFileSync("snapshot/3.fe.result.snapshot.json", decryptedMessage);
