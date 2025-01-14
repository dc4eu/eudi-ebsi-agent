import { createVerifiableCredentialJwt, verifyCredentialJwt } from "@cef-ebsi/verifiable-credential";
import { v4 as uuidv4 } from "uuid";
import { ES256KSigner } from "did-jwt";
import { base64ToBytes, resolveAlgorithm } from "./util.js";


export async function issueCredential(jwk, issuer_did, kid, subject_did) {
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
    issuer: issuer_did,
    issuanceDate: now.toISOString(),
    issued: now.toISOString(),
    validFrom: validFrom.toISOString(),
    validUntil: validUntil.toISOString(),
    expirationDate: expirationDate.toISOString(),
    credentialSubject: {
      // NOTE (GRNET): Must be did:ebsi:<...>due to enabled ebsiAuthority
      id: subject_did,
    },
    credentialSchema: {
      id: "https://api-pilot.ebsi.eu/trusted-schemas-registry/v3/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM",
      type: "FullJsonSchemaValidator2021",
    },
    termsOfUse: {
      id: `https://api-pilot.ebsi.eu/trusted-issuers-registry/v5/issuers/${issuer_did}/attributes/b40fd9b404418a44d2d9911377a03130dde450eb546c755b5b80acd782902e6d`,
      type: "IssuanceCertificate",
    },
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


  // TODO: Resolve signer type per alg
  const signer = ES256KSigner(base64ToBytes(jwk["d"]));
  const issuer = {
      did: issuer_did,
      kid,
      alg: resolveAlgorithm(jwk),
      signer,
  };
  return createVerifiableCredentialJwt(vcPayload, issuer, options);
}
