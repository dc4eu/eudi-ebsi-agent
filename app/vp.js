import { createVerifiablePresentationJwt, verifyPresentationJwt } from "@cef-ebsi/verifiable-presentation";
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
};


export async function createPresentation(jwk, kid, signerDid, holderDid, audienceDid, credentials) {
  const vpPayload = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      id: `urn:uuid:${uuidv4()}`,
      type: ["VerifiablePresentation"],
      holder: holderDid,
      verifiableCredential: credentials,
  };
  const options = {
    // OPTIONAL. Determines whether to validate the Verifiable Credential payload or not.
    // Validation is active by default.
    // NOTE: even when skipValidation is set to true, the payload must be a valid EBSI Verifiable Attestation.
    // NOTE (GRNET): We deactivate this so that we can work with non-onboarded issuer DIDs
    skipValidation: true,
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

  const signer = {
      did: signerDid,
      kid,
      alg: resolveAlgorithm(jwk),
      signer: ES256KSigner(base64ToBytes(jwk["d"])),
  };
  return createVerifiablePresentationJwt(vpPayload, signer, audienceDid, config, options);
}


export async function verifyPresentation(token, audienceDid) {
  const options = {
    // OPTIONAL. Timeout after which the requests made by the library will fail. Default: 15 seconds
    // timeout: 15_000,
    // OPTIONAL. Determines whether the JSON to JWT transformation will remove the original fields from the input payload.
    // Default: true
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
    // OPTIONAL. Determines whether to validate the signature of the VP JWT or not.
    // Validation is active by default.
    // skipSignatureValidation: false,
    // OPTIONAL. Determines whether to validate the resolution of the VP holder DID or not.
    // Validation is active by default.
    // skipHolderDidResolutionValidation: false,
    // OPTIONAL. Verification relationship.
    // One of "assertionMethod" | "authentication" | "capabilityDelegation" | "capabilityInvocation"
    // Default: "authentication"
    // proofPurpose: "authentication",
  };
  let isValid = false;
  let vpDocument;
  try {
      vpDocument = await verifyPresentationJwt(token, audienceDid, config, options);
  } catch (error) {
      return { isValid, error };
  }
  isValid = true;
  return { isValid, vpDocument };
}
