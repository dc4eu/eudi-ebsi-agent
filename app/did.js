import { randomBytes } from "node:crypto";
import { util as keyDidUtil } from "@cef-ebsi/key-did-resolver";
import { util as ebsiDidUtil } from "@cef-ebsi/ebsi-did-resolver";
import { Resolver } from "did-resolver";
import { getResolver } from "@cef-ebsi/ebsi-did-resolver";

const registry = "https://api-pilot.ebsi.eu/did-registry/v5/identifiers";
const resolverConfig = { registry };
const ebsiResolver = getResolver(resolverConfig);
const didResolver = new Resolver(ebsiResolver);

export async function createDidFromJwk(method, publicJwk) {
  if (method == "ebsi") {
      const subjectIdentifierBytes = randomBytes(16);   // TODO: Bind with key
      return ebsiDidUtil.createDid(subjectIdentifierBytes);
  } else if (method == "key") {
      return keyDidUtil.createDid(publicJwk);
  } else {
    throw Error(`Unsupported method: ${method}`);
  }
}

export async function resolveDid(did) {
  return didResolver.resolve(did);
}
