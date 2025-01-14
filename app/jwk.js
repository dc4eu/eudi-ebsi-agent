import { exportJWK, generateKeyPair } from "jose";


export async function generatePrivateJwk(algorithm) {
  const algMapping = {
    "secp256k1": "ES256K",
    "rsa": "PS256",
  }
  const label = algMapping[algorithm];
  if (!label) {
      throw Error(`Unsupported algorithm: ${algorithm}`);
  }
  const { privateKey } = await generateKeyPair(label);

  return exportJWK(privateKey);
}
