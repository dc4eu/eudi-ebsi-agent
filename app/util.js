export const base64ToBytes = (url) => {
  const normalized = url.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - (normalized.length % 4)) % 4);
  const urlPadded = normalized + padding;
  return Uint8Array.from(Buffer.from(urlPadded, "base64"));
}


export const resolveAlgorithm = (jwk) => {
  if (!jwk || !jwk.kty) {
    throw new Error("Invalid JWK: Missing 'kty' field.");
  }

  switch (jwk.kty) {
    case "EC": // Elliptic Curve
      if (!jwk.crv) {
        throw new Error("Invalid JWK: Missing 'crv' field for EC key.");
      }
      // Resolve EC algorithms based on the curve
      switch (jwk.crv) {
        case "secp256k1":
          return "ES256K"; // ECDSA using secp256k1 and SHA-256
        case "P-256":
          return "ES256"; // ECDSA using P-256 and SHA-256
        case "P-384":
          return "ES384"; // ECDSA using P-384 and SHA-384
        case "P-521":
          return "ES512"; // ECDSA using P-521 and SHA-512
        default:
          throw new Error(`Unsupported curve: ${jwk.crv}`);
      }

    case "RSA": // RSA Keys
      if (!jwk.n || !jwk.e) {
        throw new Error("Invalid JWK: Missing 'n' or 'e' field for RSA key.");
      }
      // Typically RS256 is a default for RSA
      return "RS256";

    case "oct": // Symmetric Keys
      if (!jwk.k) {
        throw new Error("Invalid JWK: Missing 'k' field for symmetric key.");
      }
      // Example: Use HS256 for HMAC with SHA-256
      return "HS256";

    default:
      throw new Error(`Unsupported key type: ${jwk.kty}`);
  }
}
