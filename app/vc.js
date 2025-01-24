import { createVerifiableCredentialJwt, verifyCredentialJwt } from "@cef-ebsi/verifiable-credential";
import { v4 as uuidv4 } from "uuid";
import { ES256KSigner } from "did-jwt";
import { base64ToBytes, resolveAlgorithm } from "./util.js";


const config = {
    // List of trusted hosts
    hosts: ["api-pilot.ebsi.eu"],
    // Defines the URI scheme
    scheme: "ebsi",
    // Defines the network config
    network: {
      // Network component, as it appears in the URI
      name: "pilot",
      // Whether the network component is optional or not
      isOptional: false,
    },
    // The list of the supported services (with their version number)
    services: {
      "did-registry": "v5",
      "trusted-issuers-registry": "v5",
      "trusted-policies-registry": "v3",
      "trusted-schemas-registry": "v3",
    },
}


export async function issueCredential(jwk, kid, issuerDid, subjectDid, claims) {
  const now = new Date();

  // valid from 0 seconds from now
  const validFrom = new Date(now.getTime() + 0 * 60 * 60 * 1000);

  // valid until 10 years from now
  const validUntil = new Date(now);
  validUntil.setFullYear(now.getFullYear() + 10);

  // expires at 5 years from now
  const expirationDate = new Date(now);
  expirationDate.setFullYear(now.getFullYear() + 5);

  const vcPayload = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      id: `urn:uuid:${uuidv4()}`,
      type: ["VerifiableCredential", "VerifiableAttestation"],
      issuer: issuerDid,
      issuanceDate: now.toISOString(),
      issued: now.toISOString(),
      validFrom: validFrom.toISOString(),
      validUntil: validUntil.toISOString(),
      expirationDate: expirationDate.toISOString(),
      credentialSubject: {
        // NOTE (GRNET): Must be did:ebsi:<...>due to enabled ebsiAuthority
        id: subjectDid,
        ...claims,
      },
      credentialSchema: {
        id: "https://api-pilot.ebsi.eu/trusted-schemas-registry/v3/schemas/zDpWGUBenmqXzurskry9Nsk6vq2R8thh9VSeoRqguoyMD",
        type: "FullJsonSchemaValidator2021",
      },
  };
  const options = {
    // OPTIONAL. Determines whether to validate the Verifiable Credential payload or not.
    // Validation is active by default.
    // NOTE: even when skipValidation is set to true, the payload must be a valid EBSI Verifiable Attestation.
    // NOTE (GRNET): We deactivate this so that we can work with non-onboarded issuer DIDs
    // skipValidation: true,
    // OPTIONAL. Timeout after which the requests made by the library will fail. Default: 15 seconds
    timeout: 15_000,
    // OPTIONAL. Determines whether to validate the accreditations of the VC issuer or not.
    // Validation is active by default.
    // skipAccreditationsValidation: false,
    // OPTIONAL. Determines whether to validate the credential status or not.
    // Validation is active by default.
    // skipStatusValidation: false,
    // OPTIONAL. Determines whether to validate the credential subject or not
    // Validation is active by default.
    // skipCredentialSubjectValidation: false,
    // OPTIONAL. Unix timestamp. Optional comparison date. Default: current date and time.
    // validAt: Date.now(),
    // OPTIONAL. Credential subject. This parameter is mandatory if the payload's `credentialSubject` is an array.
    // It must correspond to one of the IDs in the payload's `credentialSubject` array.
    // sub: "did:ebsi:z25a23eWUxQQzmAgnD9srpMM",
    // OPTIONAL. Enable Ajv verbose mode (default: false)
    // verbose: false,
    // OPTIONAL. Extra credentialSchema types. By default, the library only supports "FullJsonSchemaValidator2021" and "JsonSchema".
    // The library is not responsible for validating these extra types.
    // extraCredentialSchemaTypes: [],
  };


  // TODO: Resolve signer type per alg
  const signer = ES256KSigner(base64ToBytes(jwk["d"]));
  const issuer = {
      did: issuerDid,
      kid: `${issuerDid}#${kid}`,
      alg: resolveAlgorithm(jwk),
      signer,
  };
  return createVerifiableCredentialJwt(vcPayload, issuer, config, options);
}


export async function verifyCredential(token) {
  const options = {
    // ebsiAuthority: "api-pilot.ebsi.eu", // OPTIONAL; NOTE (GRNET): Enforces did:ebsi:<...> subject DIDs
    // OPTIONAL. List of trusted services with their respective version number (e.g. "v5").
    // Only declare this if you need to override the default versions.
    // services: {
    //   "did-registry": "v5",
    //   "trusted-issuers-registry": "v5",
    //   "trusted-policies-registry": "v3",
    //   "trusted-schemas-registry": "v3",
    // },
    // OPTIONAL. Timeout after which the requests made by the library will fail. Default: 15 seconds
    // timeout: 15_000,
    timeout: 200_000,
    // OPTIONAL. Determines whether the JSON to JWT transformation will remove the original fields from the input payload.
    // Default: true
    // removeOriginalFields: true,
    // OPTIONAL. Determines whether to validate the accreditations of the VC issuer or not.
    // Validation is active by default.
    // skipAccreditationsValidation: false,
    // OPTIONAL. Determines whether to validate the credential status or not.
    // Validation is active by default.
    // skipStatusValidation: false,
    // OPTIONAL. Determines whether to validate the credential subject or not
    // Validation is active by default.
    // skipCredentialSubjectValidation: false,
    // OPTIONAL. Unix timestamp. Optional comparison date. Default: current date and time.
    // For the JWT to be valid, `nbf` ≤ `validAt` ≤ `exp`.
    // validAt: 1686048193,
    // OPTIONAL. Determines whether or not to validate the issuer's accreditations when `termsOfUse` is missing. Default: false
    // validateAccreditationWithoutTermsOfUse: false,
    // OPTIONAL. Credential subject. This parameter is mandatory if the payload's `credentialSubject` is an array.
    // It must correspond to one of the IDs in the payload's `credentialSubject` array.
    // sub: "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbsNgeztBFXEB9FUZCoufTjXiTUZYKkcP36i2XAQCphfxBwvXG4dAaF6pdwhrMGyaLMC81fU5ECMnt4VgMQpwh3sn5vSbUpwoaTBME78noXJaTLgkCv5KkM6VgGTfWUjH8Z2",
    // OPTIONAL. Enable Ajv verbose mode (default: false)
    // verbose: false,
    // OPTIONAL. Extra credentialSchema types. By default, the library only supports "FullJsonSchemaValidator2021" and "JsonSchema".
    // The library is not responsible for validating these extra types.
    // extraCredentialSchemaTypes: [],
  };
  let isValid = false;
  let vcDocument;
  try {
      vcDocument = await verifyCredentialJwt(token, config, options);
  } catch (error) {
      return { isValid, error };
  }
  isValid = true;
  return { isValid, vcDocument };
}
