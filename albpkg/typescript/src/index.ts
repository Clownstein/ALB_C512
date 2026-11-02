/**
 * ALBPKG/1 -- signed post-quantum file packages (TypeScript / Node.js).
 *
 * A separate product from ALB_C512.  Every primitive comes from Node's
 * built-in `crypto` provider (OpenSSL underneath): ML-KEM-768, ML-DSA-65,
 * HKDF-SHA-256, and AES-256-GCM.  No cryptographic primitive is implemented
 * here, and there is no code path that reaches ALB_C512.
 *
 * This is an independent implementation of `albpkg/FORMAT.md`.  It shares no
 * code with the Python port; the two are tested against each other.
 */

import { ContactStore, type Contact } from "./contacts.ts";
import { PublicIdentity } from "./identity.ts";
import { checkProvider } from "./suite.ts";

export const VERSION = "1.0.0";

export {
  AlbpkgError,
  AuthError,
  FormatError,
  IoError,
  LimitError,
  PassphraseError,
  ProviderError,
  TrustError,
  UnsupportedError,
  type ErrorCategory,
} from "./errors.ts";

export {
  Contact,
  ContactStore,
  Trust,
  validateName,
  type TrustState,
} from "./contacts.ts";

export {
  Identity,
  PublicIdentity,
  decodePubid,
  encodePubid,
  exportPublicIdentity,
  fingerprintOf,
  fingerprintsEqual,
  formatFingerprint,
  generateIdentity,
  loadIdentity,
  migrateLegacyIdentity,
  parseIdentityPem,
  parseFingerprint,
  promptPassphrase,
  saveIdentity,
  type PassphraseProvider,
} from "./identity.ts";

export {
  Header,
  MIN_PACKAGE_SIZE,
  chunkAad,
  completionAad,
  deriveChunkKey,
  deriveCompletionKey,
  deriveMaster,
  openBuffer,
  openFile,
  sealFile,
  signatureMessage,
  type OpenOptions,
  type OpenResult,
  type ProgressHook,
  type SealOptions,
  type SealResult,
} from "./package.ts";

export {
  CHUNK_SIZE,
  FORMAT_VERSION,
  MAX_PLAINTEXT,
  SUITE_ID,
  SUITE_NAME,
  checkProvider,
} from "./suite.ts";

// Fail closed at load time if the provider cannot supply the suite.
checkProvider();

/** Import an armored public identity into `store` as an unverified contact. */
export function importContact(
  store: ContactStore,
  name: string,
  armored: string,
): Contact {
  return store.importContact(name, PublicIdentity.fromArmored(armored));
}

/** Mark a contact verified after a full out-of-band fingerprint match. */
export function verifyContact(
  store: ContactStore,
  selector: string,
  fingerprint: string,
): Contact {
  return store.verifyContact(selector, fingerprint);
}
