import { createVerifiablePresentationJwt, verifyPresentationJwt } from "@cef-ebsi/verifiable-presentation";
import { v4 as uuidv4 } from "uuid";
import { ES256KSigner } from "did-jwt";
import { base64ToBytes, resolveAlgorithm } from "./util.js";


export async function createPresentation(jwk, kid, signerDid, holderDid, audienceDid, credentials) {
  const vpPayload = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    id: `urn:uuid:${uuidv4()}`,
    type: ["VerifiablePresentation"],
    holder: holderDid,
    verifiableCredential: credentials,
  };
  const options = {
    network: "pilot", // Required: EBSI network
    hosts: ["api-pilot.ebsi.eu"], // Required: List of trusted hosts running the EBSI Core Services APIs.
    ebsiAuthority: "api-pilot.ebsi.eu", // OPTIONAL; NOTE (GRNET): Enforces did:ebsi:<...> subject DIDs
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
  return createVerifiablePresentationJwt(vpPayload, signer, audienceDid, options);
}


export async function verifyPresentation(token) {
  // TODO
}
