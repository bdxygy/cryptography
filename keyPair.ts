import { generateKeyPairSync, RSAKeyPairOptions } from "node:crypto";
import { writeFileSync } from "node:fs";

const rsaOptions: RSAKeyPairOptions<"pem", "pem"> = {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
  },
};

const { publicKey, privateKey } = generateKeyPairSync("rsa", rsaOptions);

writeFileSync("certs/public.ts", `export const publicKey = \`${publicKey}\``);
writeFileSync(
  "certs/private.ts",
  `export const privateKey = \`${privateKey}\``
);
