import {
  publicEncrypt as publicEncryptBrowser,
  randomBytes,
  createCipheriv as createCipherIvBrowser,
} from "crypto-browserify";
import { json } from "../../message";
import { readFileSync, writeFileSync } from "node:fs";
import { privateKey } from "../../certs/private";
import { publicKey } from "../../certs/public";
import {
  createDecipheriv as createDecipherIvNode,
  privateDecrypt as privateDecryptNode,
} from "node:crypto";
import { encoding, delimiter } from "../../utils";
const createAesChiperBrowser = (key: any, iv: string) =>
  createCipherIvBrowser("aes-256-gcm", key, Buffer.from(iv, encoding));

const createAesDechiperNode = (key: any, iv: string) =>
  createDecipherIvNode("aes-256-gcm", key, Buffer.from(iv, encoding));

// Generate AES key and IV
const aesKey = randomBytes(32); // AES-256 key
const ivKey = randomBytes(12).toString(encoding); // Initialization vector for GCM (12 bytes for GCM)

// Encrypt large message with AES-GCM
const frontChiper = createAesChiperBrowser(aesKey, ivKey);
let encryptedMessage = frontChiper.update(json.large, "utf8", encoding);
encryptedMessage += frontChiper.final(encoding);
const authTag = frontChiper.getAuthTag().toString(encoding); // Get the authentication tag

// Encrypt AES key with RSA
const encryptedAesKey = publicEncryptBrowser(publicKey, aesKey).toString(
  encoding
);

const snapshot = {
  data: encryptedMessage,
  session: `${ivKey}${delimiter}${authTag}${delimiter}${encryptedAesKey}`,
};

// Send into Backend
writeFileSync("snapshot/0.fe.payload.snapshot.json", JSON.stringify(snapshot));

/**
 *
 * This is a separate script to decrypt the response.
 *
 */

// Receive from Frontend
const payloadSnapshot = JSON.parse(
  readFileSync("snapshot/0.fe.payload.snapshot.json", "utf8")
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
const decryptedAesKey = privateDecryptNode(
  privateKey,
  Buffer.from(keyJson, encoding)
);

const backDechiper = createAesDechiperNode(decryptedAesKey, IvJson);

// Decrypt message with AES-GCM
backDechiper.setAuthTag(Buffer.from(authJson, encoding)); // Set the authentication tag
let decryptedMessage = backDechiper.update(dataJson, encoding, "utf8");
decryptedMessage += backDechiper.final("utf8");

writeFileSync("snapshot/1.be.result.snapshot.json", decryptedMessage);
