import test from "node:test";
import assert from "node:assert/strict";
import { createPrivateKey } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FormatError, PassphraseError } from "../src/errors.ts";
import {
  generateIdentity,
  loadIdentity,
  parseIdentityPem,
  saveIdentity,
} from "../src/identity.ts";

const passphrase = "correct horse battery staple";
const provider = (): string => passphrase;

test("identity stores two provider-readable encrypted PKCS8 objects", async () => {
  const directory = mkdtempSync(join(tmpdir(), "albpkg-pkcs8-"));
  try {
    const target = join(directory, "identity.key");
    const identity = generateIdentity();
    await saveIdentity(identity, target, { passphraseProvider: provider });
    const objects = parseIdentityPem(readFileSync(target));
    assert.equal(createPrivateKey({ key: objects.kem, format: "der", type: "pkcs8", passphrase }).asymmetricKeyType, "ml-kem-768");
    assert.equal(createPrivateKey({ key: objects.sig, format: "der", type: "pkcs8", passphrase }).asymmetricKeyType, "ml-dsa-65");
    assert.deepEqual((await loadIdentity(target, { passphraseProvider: provider })).fingerprint, identity.fingerprint);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("identity parser rejects legacy, CRLF, and trailing data without fallback", async () => {
  const directory = mkdtempSync(join(tmpdir(), "albpkg-pkcs8-"));
  try {
    const target = join(directory, "identity.key");
    await saveIdentity(generateIdentity(), target, { passphraseProvider: provider });
    const valid = readFileSync(target);
    for (const invalid of [
      Buffer.concat([valid, Buffer.from("\n")]),
      Buffer.from(valid.toString("ascii").replaceAll("\n", "\r\n"), "ascii"),
      Buffer.from("ALBPKSK2legacy data", "ascii"),
    ]) {
      writeFileSync(target, invalid);
      await assert.rejects(loadIdentity(target, { passphraseProvider: provider }), FormatError);
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("wrong PKCS8 passphrase has one non-oracular error", async () => {
  const directory = mkdtempSync(join(tmpdir(), "albpkg-pkcs8-"));
  try {
    const target = join(directory, "identity.key");
    await saveIdentity(generateIdentity(), target, { passphraseProvider: provider });
    await assert.rejects(
      loadIdentity(target, { passphraseProvider: () => "wrong passphrase" }),
      (error: unknown) => error instanceof PassphraseError && error.message.includes("wrong or the key has been altered"),
    );
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
