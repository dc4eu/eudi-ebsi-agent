import { getResolver } from "@cef-ebsi/ebsi-did-resolver";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { Resolver } from "did-resolver";

const registry = "https://api-pilot.ebsi.eu/did-registry/v5/identifiers";
const resolverConfig = { registry };
const ebsiResolver = getResolver(resolverConfig);
const didResolver = new Resolver(ebsiResolver);

export async function createDidFromJwk(method, publicJwk) {
  const methodMapping = {
    "key": "NATURAL_PERSON",
    "ebsi": "LEGAL_ENTITY",
  };

  const label = methodMapping[method];
  if (!label) {
      throw Error(`Unsupported method: ${method}`);
  }
  return EbsiWallet.createDid(label, publicJwk);
}

export async function resolveDid(did) {
  return didResolver.resolve(did);
}
