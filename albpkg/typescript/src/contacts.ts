/**
 * Contact store: import, manual fingerprint verification, revocation.
 *
 * FORMAT.md section 2.5.  An imported contact starts `unverified` and is
 * useless until the operator confirms the full 256-bit fingerprint out of
 * band.  Replacing a name's key resets trust; revocation is permanent until
 * explicitly undone.
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import * as path from "node:path";

import { FormatError, IoError, TrustError } from "./errors.ts";
import { withAtomicOutput } from "./fsutil.ts";
import {
  PublicIdentity,
  fingerprintsEqual,
  formatFingerprint,
  parseFingerprint,
} from "./identity.ts";

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$/;
const MAX_CONTACT_FILE = 1 << 16;

export const Trust = {
  UNVERIFIED: "unverified",
  VERIFIED: "verified",
  REVOKED: "revoked",
} as const;

export type TrustState = (typeof Trust)[keyof typeof Trust];

const TRUST_VALUES: readonly string[] = Object.values(Trust);

export class Contact {
  readonly name: string;
  readonly public: PublicIdentity;
  readonly trust: TrustState;

  constructor(name: string, publicIdentity: PublicIdentity, trust: TrustState) {
    this.name = name;
    this.public = publicIdentity;
    this.trust = trust;
  }

  get fingerprint(): Buffer {
    return this.public.fingerprint;
  }

  get fingerprintText(): string {
    return formatFingerprint(this.fingerprint);
  }

  /** Throw unless this contact may be sealed to or accepted from. */
  requireUsable(): void {
    if (this.trust === Trust.REVOKED) {
      throw new TrustError(`contact '${this.name}' is revoked`);
    }
    if (this.trust !== Trust.VERIFIED) {
      throw new TrustError(
        `contact '${this.name}' is unverified; confirm the full fingerprint ` +
          `${this.fingerprintText} out of band and run 'verify-contact' first`,
      );
    }
  }
}

export function validateName(name: string): string {
  if (typeof name !== "string" || !NAME_RE.test(name)) {
    throw new FormatError(
      "contact name must be 1-64 characters of [A-Za-z0-9._@+-] starting " +
        "with an alphanumeric",
    );
  }
  return name;
}

/**
 * A directory of one JSON file per contact, keyed by fingerprint.
 *
 * Files are keyed by fingerprint rather than by name so that a name collision
 * can never silently substitute one key for another; the name is an attribute
 * inside the record.
 */
export class ContactStore {
  readonly directory: string;

  constructor(directory: string) {
    this.directory = directory;
    mkdirSync(directory, { recursive: true });
  }

  #pathFor(fpr: Buffer): string {
    return path.join(this.directory, `${fpr.toString("hex")}.contact`);
  }

  #loadFile(file: string): Contact {
    let raw: string;
    try {
      if (statSync(file).size > MAX_CONTACT_FILE) {
        throw new FormatError(
          `contact file ${path.basename(file)} is implausibly large`,
        );
      }
      raw = readFileSync(file, "utf8");
    } catch (cause) {
      if (cause instanceof FormatError) throw cause;
      throw new IoError(`cannot read contact file ${path.basename(file)}`, {
        cause,
      });
    }

    let record: unknown;
    try {
      record = JSON.parse(raw);
    } catch (cause) {
      throw new FormatError(
        `contact file ${path.basename(file)} is not valid JSON`,
        { cause },
      );
    }
    if (typeof record !== "object" || record === null || Array.isArray(record)) {
      throw new FormatError(`contact file ${path.basename(file)} is not an object`);
    }

    const fields = record as Record<string, unknown>;
    const expected = ["name", "pubid", "trust", "version"];
    const actual = Object.keys(fields).sort();
    if (
      actual.length !== expected.length ||
      !actual.every((key, index) => key === expected[index])
    ) {
      throw new FormatError(
        `contact file ${path.basename(file)} has unexpected fields`,
      );
    }
    if (fields["version"] !== 1) {
      throw new FormatError(
        `unsupported contact record version in ${path.basename(file)}`,
      );
    }

    const name = validateName(String(fields["name"]));
    const trust = String(fields["trust"]);
    if (!TRUST_VALUES.includes(trust)) {
      throw new FormatError(`unknown trust state in ${path.basename(file)}`);
    }

    const pubidText = String(fields["pubid"]);
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(pubidText)) {
      throw new FormatError(
        `contact file ${path.basename(file)} has a malformed key`,
      );
    }
    const pubid = Buffer.from(pubidText, "base64");
    const publicIdentity = PublicIdentity.fromPubid(pubid);

    if (
      path.basename(file) !== `${publicIdentity.fingerprint.toString("hex")}.contact`
    ) {
      throw new FormatError(
        `contact file ${path.basename(file)} does not match its own key fingerprint`,
      );
    }

    return new Contact(name, publicIdentity, trust as TrustState);
  }

  get(fpr: Buffer): Contact | undefined {
    const file = this.#pathFor(fpr);
    if (!existsSync(file)) return undefined;
    return this.#loadFile(file);
  }

  require(fpr: Buffer): Contact {
    const contact = this.get(fpr);
    if (contact === undefined) {
      throw new TrustError(
        `no contact for fingerprint ${formatFingerprint(fpr)}; ` +
          "import and verify it first",
      );
    }
    return contact;
  }

  byName(name: string): Contact {
    validateName(name);
    const matches = this.list().filter((contact) => contact.name === name);
    if (matches.length === 0) throw new TrustError(`no contact named '${name}'`);
    if (matches.length > 1) {
      throw new TrustError(
        `'${name}' is bound to ${matches.length} different keys; resolve it by fingerprint`,
      );
    }
    return matches[0]!;
  }

  /** Accept a fingerprint (grouped or plain hex) or a contact name. */
  resolve(selector: string): Contact {
    let fpr: Buffer;
    try {
      fpr = parseFingerprint(selector);
    } catch {
      return this.byName(selector);
    }
    return this.require(fpr);
  }

  list(): Contact[] {
    const files = readdirSync(this.directory)
      .filter((name) => name.endsWith(".contact"))
      .sort();
    const contacts = files.map((name) =>
      this.#loadFile(path.join(this.directory, name)),
    );
    contacts.sort((a, b) => {
      if (a.name !== b.name) return a.name < b.name ? -1 : 1;
      return Buffer.compare(a.fingerprint, b.fingerprint);
    });
    return contacts;
  }

  #write(contact: Contact): void {
    const record = {
      name: contact.name,
      pubid: contact.public.pubid.toString("base64"),
      trust: contact.trust,
      version: 1,
    };
    const blob = Buffer.from(
      `${JSON.stringify(record, Object.keys(record).sort(), 2)}\n`,
      "utf8",
    );
    withAtomicOutput(this.#pathFor(contact.fingerprint), { overwrite: true }, ({ fd }) => {
      writeSync(fd, blob);
    });
  }

  /**
   * Import a public identity under `name`, always as `unverified`.
   *
   * Re-importing the identical key is a no-op that preserves the existing
   * trust state.  Importing a *different* key under a name that is already
   * bound elsewhere is a key replacement: the new key is stored unverified and
   * the old one is demoted, so a stale verified key can never be selected by
   * name.
   */
  importContact(name: string, publicIdentity: PublicIdentity): Contact {
    validateName(name);
    const existing = this.get(publicIdentity.fingerprint);
    if (existing !== undefined) {
      if (existing.name !== name) {
        throw new TrustError(
          `this key is already stored as '${existing.name}'; ` +
            "remove it before importing it under a different name",
        );
      }
      return existing;
    }

    const replaced = this.list().filter((contact) => contact.name === name);
    const contact = new Contact(name, publicIdentity, Trust.UNVERIFIED);
    for (const old of replaced) {
      if (old.trust !== Trust.REVOKED) {
        this.#write(new Contact(old.name, old.public, Trust.UNVERIFIED));
      }
    }
    // Invalidate old fingerprints before publishing the replacement. A
    // failed write must not leave an old verified key beside the new key.
    this.#write(contact);
    return contact;
  }

  /** Mark a contact verified, but only on a full fingerprint match. */
  verifyContact(selector: string, presentedFingerprint: string): Contact {
    const contact = this.resolve(selector);
    const presented = parseFingerprint(presentedFingerprint);
    if (!fingerprintsEqual(presented, contact.fingerprint)) {
      throw new TrustError(
        "the fingerprint you entered does not match the stored key; " +
          "the contact remains unverified",
      );
    }
    if (contact.trust === Trust.REVOKED) {
      throw new TrustError(
        `contact '${contact.name}' is revoked; un-revoke it deliberately before verifying`,
      );
    }
    const updated = new Contact(contact.name, contact.public, Trust.VERIFIED);
    this.#write(updated);
    return updated;
  }

  setTrust(selector: string, trust: TrustState): Contact {
    const contact = this.resolve(selector);
    const updated = new Contact(contact.name, contact.public, trust);
    this.#write(updated);
    return updated;
  }

  revoke(selector: string): Contact {
    return this.setTrust(selector, Trust.REVOKED);
  }

  remove(selector: string): Contact {
    const contact = this.resolve(selector);
    unlinkSync(this.#pathFor(contact.fingerprint));
    return contact;
  }
}
