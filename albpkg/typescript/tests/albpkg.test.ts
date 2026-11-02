/**
 * Acceptance tests for the ALBPKG/1 TypeScript reference implementation.
 *
 * Mirrors the Python suite's coverage: round-trips including empty files and
 * chunk boundaries, and explicit rejection of wrong recipients, untrusted or
 * revoked senders, altered headers, substituted encapsulations, bad signatures
 * and tags, reordered or duplicated chunks, truncation, appended data, and
 * overflow.
 *
 * Run:  node --test albpkg/typescript/tests/
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  createHash,
  encapsulate,
  randomBytes,
  sign as signWith,
} from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import * as suite from "../src/suite.ts";
import { Contact, ContactStore, Trust } from "../src/contacts.ts";
import {
  AuthError,
  FormatError,
  IoError,
  LimitError,
  PassphraseError,
  TrustError,
  UnsupportedError,
} from "../src/errors.ts";
import {
  Identity,
  PublicIdentity,
  generateIdentity,
  loadIdentity,
  parseFingerprint,
  saveIdentity,
} from "../src/identity.ts";
import { permissionsAreOwnerOnly } from "../src/fsutil.ts";
import {
  Header,
  deriveChunkKey,
  deriveCompletionKey,
  deriveMaster,
  openBuffer,
  openFile,
  sealFile,
  signatureMessage,
} from "../src/package.ts";
import { ByteReader, checkedAdd, checkedMul, requireIndex, u32 } from "../src/wire.ts";

const PASSPHRASE = "correct horse battery staple";
const pp = (): string => PASSPHRASE;

const CHUNK = suite.CHUNK_SIZE;

// Generating post-quantum keypairs is not free; share three identities across
// the whole suite rather than per test.
const alice = generateIdentity();
const bob = generateIdentity();
const mallory = generateIdentity();

const tempRoots: string[] = [];

function tmpdir(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "albpkg-ts-"));
  tempRoots.push(dir);
  return dir;
}

process.on("exit", () => {
  for (const dir of tempRoots) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
});

function trustingStore(dir: string, who: Identity, name: string): ContactStore {
  const store = new ContactStore(path.join(dir, "contacts"));
  store.importContact(name, who.public);
  store.verifyContact(name, who.public.fingerprint.toString("hex"));
  return store;
}

function seal(
  dir: string,
  sender: Identity,
  recipient: PublicIdentity,
  data: Buffer,
  name = "pkg.albpkg",
): string {
  const src = path.join(dir, `${name}.in`);
  writeFileSync(src, data);
  const out = path.join(dir, name);
  sealFile({
    sender,
    recipient: new Contact("fixture", recipient, Trust.VERIFIED),
    inputPath: src,
    outputPath: out,
    overwrite: true,
  });
  return out;
}

function open(
  pkg: string,
  recipient: Identity,
  contacts: ContactStore,
  out: string,
): ReturnType<typeof openFile> {
  return openFile({
    recipient,
    contacts,
    packagePath: pkg,
    outputPath: out,
    overwrite: true,
  });
}

/** Re-sign a tampered body so a test isolates a non-signature defence. */
function resign(bodyOrFull: Buffer, sender: Identity): Buffer {
  let body = bodyOrFull;
  if (
    bodyOrFull.length > suite.SIG_TRAILER_LEN &&
    bodyOrFull.subarray(-8).equals(suite.SIG_TRAILER_MAGIC)
  ) {
    body = bodyOrFull.subarray(
      0,
      bodyOrFull.length - suite.SIG_TRAILER_LEN - suite.SIG_LEN,
    );
  }
  const signature = signWith(
    null,
    signatureMessage(createHash("sha512").update(body).digest()),
    sender.sigPrivate,
  );
  return Buffer.concat([
    body,
    signature,
    u32(signature.length),
    suite.SIG_TRAILER_MAGIC,
  ]);
}

function flip(blob: Buffer, offset: number): Buffer {
  const out = Buffer.from(blob);
  out[offset] = out[offset]! ^ 0x01;
  return out;
}

// ---- Identity and fingerprints ------------------------------------------

test("identity keys are independent", () => {
  assert.notDeepEqual(
    alice.public.kemPublicBytes,
    alice.public.sigPublicBytes,
  );
  assert.equal(alice.public.pubid.length, 3150);
  assert.equal(suite.PUBID_LEN, 3150);
});

test("fingerprint covers both keys", () => {
  const swapped = new PublicIdentity(
    alice.public.kemPublicBytes,
    bob.public.sigPublicBytes,
  );
  assert.notEqual(
    swapped.fingerprint.toString("hex"),
    alice.public.fingerprint.toString("hex"),
  );
  assert.notEqual(
    swapped.fingerprint.toString("hex"),
    bob.public.fingerprint.toString("hex"),
  );
});

test("fingerprint formatting round trip", () => {
  const text = alice.public.fingerprintText;
  assert.equal(text.length, 64 + 7);
  assert.deepEqual(parseFingerprint(text), alice.public.fingerprint);
  assert.deepEqual(
    parseFingerprint(alice.public.fingerprint.toString("hex")),
    alice.public.fingerprint,
  );
});

test("truncated or invalid fingerprints are rejected", () => {
  for (const bad of ["", "abcd", "1a2b3c4d", "z".repeat(64), "ab".repeat(33)]) {
    assert.throws(() => parseFingerprint(bad), FormatError);
  }
});

test("armored round trip", () => {
  const restored = PublicIdentity.fromArmored(alice.public.toArmored());
  assert.deepEqual(restored.fingerprint, alice.public.fingerprint);
});

test("armored fingerprint header must match the keys", () => {
  const armored = alice.public
    .toArmored()
    .replace(
      alice.public.fingerprint.toString("hex"),
      bob.public.fingerprint.toString("hex"),
    );
  assert.throws(() => PublicIdentity.fromArmored(armored), FormatError);
});

test("armored body corruption is rejected", () => {
  const lines = alice.public.toArmored().split("\n");
  const line = lines[3]!;
  lines[3] = (line[0] === "A" ? "B" : "A") + line.slice(1);
  assert.throws(() => PublicIdentity.fromArmored(lines.join("\n")), FormatError);
});

test("noncanonical public identities are rejected", () => {
  const base = alice.public.pubid;
  const mutations: Array<(b: Buffer) => Buffer> = [
    (b) => b.subarray(0, b.length - 1),
    (b) => Buffer.concat([b, Buffer.from([0])]),
    (b) => Buffer.concat([Buffer.from("XXXXXXXX"), b.subarray(8)]),
    (b) => Buffer.concat([b.subarray(0, 8), Buffer.from([0, 2]), b.subarray(10)]),
    (b) => Buffer.concat([b.subarray(0, 10), Buffer.from([0, 16]), b.subarray(12)]),
  ];
  for (const mutate of mutations) {
    assert.throws(
      () => PublicIdentity.fromPubid(mutate(Buffer.from(base))),
      (error: unknown) =>
        error instanceof FormatError || error instanceof UnsupportedError,
    );
  }
});

// ---- Private identity storage -------------------------------------------

test("identity file round trip and permissions", async () => {
  const dir = tmpdir();
  const file = path.join(dir, "id.key");
  await saveIdentity(alice, file, { passphraseProvider: pp });
  assert.ok(permissionsAreOwnerOnly(file));
  const loaded = await loadIdentity(file, { passphraseProvider: pp });
  assert.deepEqual(loaded.fingerprint, alice.fingerprint);
});

test("identity file rejects the wrong passphrase", async () => {
  const dir = tmpdir();
  const file = path.join(dir, "id.key");
  await saveIdentity(alice, file, { passphraseProvider: pp });
  await assert.rejects(
    () => loadIdentity(file, { passphraseProvider: () => "wrong passphrase" }),
    PassphraseError,
  );
});

test("short passphrases are rejected", async () => {
  const dir = tmpdir();
  await assert.rejects(
    () =>
      saveIdentity(alice, path.join(dir, "id.key"), {
        passphraseProvider: () => "short",
      }),
    PassphraseError,
  );
});

test("identity file truncation is rejected", async () => {
  const dir = tmpdir();
  const file = path.join(dir, "id.key");
  await saveIdentity(alice, file, { passphraseProvider: pp });
  const blob = readFileSync(file);
  writeFileSync(file, blob.subarray(0, blob.length - 5));
  await assert.rejects(() => loadIdentity(file, { passphraseProvider: pp }), FormatError);
});

test("identity file trailing bytes are rejected", async () => {
  const dir = tmpdir();
  const file = path.join(dir, "id.key");
  await saveIdentity(alice, file, { passphraseProvider: pp });
  writeFileSync(file, Buffer.concat([readFileSync(file), Buffer.from([0])]));
  await assert.rejects(() => loadIdentity(file, { passphraseProvider: pp }), FormatError);
});

test("saveIdentity does not clobber without overwrite", async () => {
  const dir = tmpdir();
  const file = path.join(dir, "id.key");
  await saveIdentity(alice, file, { passphraseProvider: pp });
  const original = readFileSync(file);
  await assert.rejects(
    () => saveIdentity(bob, file, { passphraseProvider: pp }),
    IoError,
  );
  assert.deepEqual(readFileSync(file), original);
});

// ---- Contact trust -------------------------------------------------------

test("import is unverified and unusable", () => {
  const store = new ContactStore(path.join(tmpdir(), "contacts"));
  const contact = store.importContact("alice", alice.public);
  assert.equal(contact.trust, Trust.UNVERIFIED);
  assert.throws(() => contact.requireUsable(), TrustError);
});

test("verify requires the exact fingerprint", () => {
  const store = new ContactStore(path.join(tmpdir(), "contacts"));
  store.importContact("alice", alice.public);
  assert.throws(
    () => store.verifyContact("alice", bob.public.fingerprint.toString("hex")),
    TrustError,
  );
  assert.equal(store.byName("alice").trust, Trust.UNVERIFIED);
  store.verifyContact("alice", alice.public.fingerprintText);
  assert.equal(store.byName("alice").trust, Trust.VERIFIED);
});

test("key replacement resets trust", () => {
  const store = new ContactStore(path.join(tmpdir(), "contacts"));
  store.importContact("alice", alice.public);
  store.verifyContact("alice", alice.public.fingerprint.toString("hex"));
  store.importContact("alice", bob.public);
  for (const contact of store.list()) {
    assert.equal(contact.trust, Trust.UNVERIFIED);
  }
  assert.throws(() => store.byName("alice"), TrustError);
});

test("failed replacement demotes the old fingerprint first", () => {
  const store = new ContactStore(path.join(tmpdir(), "contacts"));
  store.importContact("alice", alice.public);
  store.verifyContact("alice", alice.public.fingerprint.toString("hex"));
  const realList = store.list.bind(store);
  store.list = () => {
    const contacts = realList();
    // This happens after importContact's existing-key lookup and before its
    // writes, so only publication of the replacement fails.
    const blocked = path.join(store.directory, `${bob.public.fingerprint.toString("hex")}.contact`);
    mkdirSync(blocked);
    store.list = realList;
    return contacts;
  };
  assert.throws(() => store.importContact("alice", bob.public));
  assert.equal(store.require(alice.public.fingerprint).trust, Trust.UNVERIFIED);
});

test("re-importing the same key preserves trust", () => {
  const store = new ContactStore(path.join(tmpdir(), "contacts"));
  store.importContact("alice", alice.public);
  store.verifyContact("alice", alice.public.fingerprint.toString("hex"));
  assert.equal(store.importContact("alice", alice.public).trust, Trust.VERIFIED);
});

test("revoked contacts are rejected", () => {
  const store = new ContactStore(path.join(tmpdir(), "contacts"));
  store.importContact("alice", alice.public);
  store.verifyContact("alice", alice.public.fingerprint.toString("hex"));
  store.revoke("alice");
  assert.throws(() => store.byName("alice").requireUsable(), TrustError);
});

test("contact file tampering is rejected", () => {
  const dir = tmpdir();
  const store = new ContactStore(path.join(dir, "contacts"));
  store.importContact("alice", alice.public);
  const file = path.join(
    store.directory,
    readdirSync(store.directory).find((n) => n.endsWith(".contact"))!,
  );
  writeFileSync(file, readFileSync(file, "utf8").replace('"unverified"', '"nonsense"'));
  assert.throws(() => store.list(), FormatError);
});

test("a contact file renamed to the wrong fingerprint is rejected", () => {
  const dir = tmpdir();
  const store = new ContactStore(path.join(dir, "contacts"));
  store.importContact("alice", alice.public);
  const name = readdirSync(store.directory).find((n) => n.endsWith(".contact"))!;
  renameSync(
    path.join(store.directory, name),
    path.join(store.directory, `${bob.public.fingerprint.toString("hex")}.contact`),
  );
  assert.throws(() => store.list(), FormatError);
});

// ---- Round trip ----------------------------------------------------------

for (const size of [0, 1, 1024, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 2 * CHUNK + 7]) {
  test(`round trip at ${size} bytes`, () => {
    const dir = tmpdir();
    const store = trustingStore(dir, alice, "alice");
    const data = randomBytes(size);
    const pkg = seal(dir, alice, bob.public, data);
    const out = path.join(dir, "out.bin");
    const result = open(pkg, bob, store, out);
    assert.deepEqual(readFileSync(out), data);
    assert.equal(result.totalBytes, size);
    assert.equal(result.senderName, "alice");
    assert.equal(result.chunkCount, Math.max(1, Math.ceil(size / CHUNK)));
  });
}

test("an empty file produces one final chunk", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, Buffer.alloc(0));
  const out = path.join(dir, "out.bin");
  const result = open(pkg, bob, store, out);
  assert.equal(result.chunkCount, 1);
  assert.equal(result.totalBytes, 0);
  assert.equal(readFileSync(out).length, 0);
});

test("package ids and ciphertexts are fresh", () => {
  const dir = tmpdir();
  const data = Buffer.from("same plaintext every time");
  const a = seal(dir, alice, bob.public, data, "a.albpkg");
  const b = seal(dir, alice, bob.public, data, "b.albpkg");
  assert.notDeepEqual(readFileSync(a), readFileSync(b));
  const ha = Header.parse(readFileSync(a).subarray(0, suite.HEADER_LEN));
  const hb = Header.parse(readFileSync(b).subarray(0, suite.HEADER_LEN));
  assert.notDeepEqual(ha.packageId, hb.packageId);
  assert.notDeepEqual(ha.kemCt, hb.kemCt);
});

test("a package held in memory is spooled and opened", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const data = randomBytes(5000);
  const pkg = seal(dir, alice, bob.public, data);
  const out = path.join(dir, "out.bin");
  const result = openBuffer({
    recipient: bob,
    contacts: store,
    data: readFileSync(pkg),
    outputPath: out,
    overwrite: true,
  });
  assert.equal(result.totalBytes, data.length);
  assert.deepEqual(readFileSync(out), data);
});

// ---- Trust enforcement on open ------------------------------------------

test("wrong recipient is rejected", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, Buffer.from("for bob only"));
  assert.throws(
    () => open(pkg, mallory, store, path.join(dir, "out.bin")),
    TrustError,
  );
});

test("unknown sender is rejected", () => {
  const dir = tmpdir();
  const store = new ContactStore(path.join(dir, "contacts"));
  const pkg = seal(dir, alice, bob.public, Buffer.from("hello"));
  assert.throws(() => open(pkg, bob, store, path.join(dir, "out.bin")), TrustError);
});

test("unverified sender is rejected", () => {
  const dir = tmpdir();
  const store = new ContactStore(path.join(dir, "contacts"));
  store.importContact("alice", alice.public);
  const pkg = seal(dir, alice, bob.public, Buffer.from("hello"));
  assert.throws(() => open(pkg, bob, store, path.join(dir, "out.bin")), TrustError);
});

test("revoked sender is rejected", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, Buffer.from("hello"));
  store.revoke("alice");
  assert.throws(() => open(pkg, bob, store, path.join(dir, "out.bin")), TrustError);
});

test("sealing to an unverified contact is refused", () => {
  const dir = tmpdir();
  const store = new ContactStore(path.join(dir, "contacts"));
  const contact = store.importContact("bob", bob.public);
  const src = path.join(dir, "in.bin");
  writeFileSync(src, "x");
  const out = path.join(dir, "out.albpkg");
  assert.throws(
    () =>
      sealFile({ sender: alice, recipient: contact, inputPath: src, outputPath: out }),
    TrustError,
  );
  assert.ok(!existsSync(out));
});

test("sealing to a revoked contact is refused", () => {
  const dir = tmpdir();
  const store = new ContactStore(path.join(dir, "contacts"));
  store.importContact("bob", bob.public);
  store.verifyContact("bob", bob.public.fingerprint.toString("hex"));
  const contact = store.revoke("bob");
  const src = path.join(dir, "in.bin");
  writeFileSync(src, "x");
  assert.throws(
    () =>
      sealFile({
        sender: alice,
        recipient: contact,
        inputPath: src,
        outputPath: path.join(dir, "out.albpkg"),
      }),
    TrustError,
  );
});

// ---- Tamper matrix -------------------------------------------------------

const TAMPER_OFFSETS: Record<string, number> = {
  magic: 0,
  format_version: 8,
  suite_id: 10,
  header_len: 15,
  flags: 16,
  chunk_size: 23,
  sender_fpr: 24,
  recipient_fpr: 56,
  package_id: 88,
  kem_ct_len: 105,
  kem_ct: 110,
};

for (const [field, offset] of Object.entries(TAMPER_OFFSETS)) {
  test(`header tampering rejected: ${field}`, () => {
    const dir = tmpdir();
    const store = trustingStore(dir, alice, "alice");
    const pkg = seal(dir, alice, bob.public, randomBytes(4096));
    writeFileSync(pkg, flip(readFileSync(pkg), offset));
    const out = path.join(dir, "out.bin");
    assert.throws(() => open(pkg, bob, store, out));
    assert.ok(!existsSync(out));
  });
}

test("substituted encapsulation is rejected", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, randomBytes(2048));
  const blob = Buffer.from(readFileSync(pkg));
  const other = Buffer.from(encapsulate(mallory.public.kemKey()).ciphertext);
  const start = 8 + 2 + 2 + 4 + 4 + 4 + 32 + 32 + 16 + 2;
  other.copy(blob, start);
  writeFileSync(pkg, blob);
  assert.throws(() => open(pkg, bob, store, path.join(dir, "out.bin")));
});

test("a bad signature is rejected", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, randomBytes(2048));
  const blob = Buffer.from(readFileSync(pkg));
  const sigStart = blob.length - suite.SIG_TRAILER_LEN - suite.SIG_LEN;
  blob[sigStart + 10] = blob[sigStart + 10]! ^ 0xff;
  writeFileSync(pkg, blob);
  assert.throws(() => open(pkg, bob, store, path.join(dir, "out.bin")), AuthError);
});

test("a signature from another sender is rejected", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, randomBytes(1024));
  writeFileSync(pkg, resign(readFileSync(pkg), mallory));
  assert.throws(() => open(pkg, bob, store, path.join(dir, "out.bin")), AuthError);
});

test("ciphertext tampering is rejected", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, randomBytes(4096));
  writeFileSync(pkg, flip(readFileSync(pkg), suite.HEADER_LEN + 20));
  const out = path.join(dir, "out.bin");
  assert.throws(() => open(pkg, bob, store, out), AuthError);
  assert.ok(!existsSync(out));
});

test("chunk reordering is rejected", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, randomBytes(3 * CHUNK));
  const blob = Buffer.from(readFileSync(pkg));

  const rec = 5 + CHUNK + suite.AEAD_TAG_LEN;
  const a0 = suite.HEADER_LEN;
  const swapped = Buffer.concat([
    blob.subarray(0, a0),
    blob.subarray(a0 + rec, a0 + 2 * rec),
    blob.subarray(a0, a0 + rec),
    blob.subarray(a0 + 2 * rec),
  ]);
  writeFileSync(pkg, resign(swapped, alice));
  assert.throws(() => open(pkg, bob, store, path.join(dir, "out.bin")), AuthError);
});

test("chunk duplication is rejected", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, randomBytes(2 * CHUNK));
  const blob = Buffer.from(readFileSync(pkg));

  const rec = 5 + CHUNK + suite.AEAD_TAG_LEN;
  const a0 = suite.HEADER_LEN;
  blob.copy(blob, a0 + rec, a0, a0 + rec);
  writeFileSync(pkg, resign(blob, alice));
  assert.throws(() => open(pkg, bob, store, path.join(dir, "out.bin")));
});

test("dropping a whole chunk is rejected by the completion record", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, randomBytes(2 * CHUNK));
  const blob = readFileSync(pkg);

  const rec = 5 + CHUNK + suite.AEAD_TAG_LEN;
  const bodyLen = blob.length - suite.SIG_TRAILER_LEN - suite.SIG_LEN;
  const completion = blob.subarray(bodyLen - suite.COMPLETION_LEN, bodyLen);
  const kept = Buffer.concat([blob.subarray(0, suite.HEADER_LEN + rec), completion]);
  writeFileSync(pkg, resign(kept, alice));
  assert.throws(() => open(pkg, bob, store, path.join(dir, "out.bin")));
});

test("byte truncation is rejected", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, randomBytes(4096));
  const blob = readFileSync(pkg);
  writeFileSync(pkg, blob.subarray(0, blob.length - 1));
  assert.throws(() => open(pkg, bob, store, path.join(dir, "out.bin")));
});

test("appended data is rejected", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, randomBytes(4096));
  writeFileSync(pkg, Buffer.concat([readFileSync(pkg), Buffer.from("extra")]));
  assert.throws(() => open(pkg, bob, store, path.join(dir, "out.bin")));
});

test("a moved final marker is rejected", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, randomBytes(1000));
  const blob = Buffer.from(readFileSync(pkg));
  blob[suite.HEADER_LEN] = 0;
  writeFileSync(pkg, resign(blob, alice));
  assert.throws(() => open(pkg, bob, store, path.join(dir, "out.bin")));
});

test("an oversized chunk length is rejected", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, Buffer.from("small"));
  const blob = Buffer.from(readFileSync(pkg));
  u32(0xffffffff).copy(blob, suite.HEADER_LEN + 1);
  writeFileSync(pkg, resign(blob, alice));
  assert.throws(() => open(pkg, bob, store, path.join(dir, "out.bin")));
});

test("a noncanonical final marker is rejected", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, Buffer.from("small"));
  const blob = Buffer.from(readFileSync(pkg));
  blob[suite.HEADER_LEN] = 2;
  writeFileSync(pkg, resign(blob, alice));
  assert.throws(() => open(pkg, bob, store, path.join(dir, "out.bin")), FormatError);
});

test("completion record tampering is rejected", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, randomBytes(1024));
  const blob = Buffer.from(readFileSync(pkg));
  const bodyLen = blob.length - suite.SIG_TRAILER_LEN - suite.SIG_LEN;
  blob[bodyLen - 1] = blob[bodyLen - 1]! ^ 0x01;
  writeFileSync(pkg, resign(blob, alice));
  assert.throws(() => open(pkg, bob, store, path.join(dir, "out.bin")), AuthError);
});

test("the trailer magic is required", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, Buffer.from("x"));
  const blob = Buffer.from(readFileSync(pkg));
  blob[blob.length - 1] = blob[blob.length - 1]! ^ 0xff;
  writeFileSync(pkg, blob);
  assert.throws(() => open(pkg, bob, store, path.join(dir, "out.bin")), FormatError);
});

test("a noncanonical signature length is rejected", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, Buffer.from("x"));
  const blob = Buffer.from(readFileSync(pkg));
  u32(suite.SIG_LEN + 1).copy(blob, blob.length - suite.SIG_TRAILER_LEN);
  writeFileSync(pkg, blob);
  assert.throws(() => open(pkg, bob, store, path.join(dir, "out.bin")), FormatError);
});

test("cross-package splicing is rejected", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const a = seal(dir, alice, bob.public, randomBytes(2048), "a.albpkg");
  const b = seal(dir, alice, bob.public, randomBytes(2048), "b.albpkg");
  const spliced = Buffer.concat([
    readFileSync(a).subarray(0, suite.HEADER_LEN),
    readFileSync(b).subarray(suite.HEADER_LEN),
  ]);
  const target = path.join(dir, "spliced.albpkg");
  writeFileSync(target, resign(spliced, alice));
  assert.throws(() => open(target, bob, store, path.join(dir, "out.bin")), AuthError);
});

// ---- Output safety -------------------------------------------------------

test("destination is preserved on failure", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, randomBytes(4096));
  writeFileSync(pkg, flip(readFileSync(pkg), suite.HEADER_LEN + 30));

  const out = path.join(dir, "out.bin");
  writeFileSync(out, "PRECIOUS ORIGINAL");
  assert.throws(
    () =>
      openFile({
        recipient: bob,
        contacts: store,
        packagePath: pkg,
        outputPath: out,
        overwrite: true,
      }),
    AuthError,
  );
  assert.equal(readFileSync(out, "utf8"), "PRECIOUS ORIGINAL");
});

test("no overwrite without the flag", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, Buffer.from("hello"));
  const out = path.join(dir, "out.bin");
  writeFileSync(out, "ORIGINAL");
  assert.throws(
    () =>
      openFile({
        recipient: bob,
        contacts: store,
        packagePath: pkg,
        outputPath: out,
        overwrite: false,
      }),
    IoError,
  );
  assert.equal(readFileSync(out, "utf8"), "ORIGINAL");
});

test("no temporary files are left behind", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, randomBytes(4096));
  open(pkg, bob, store, path.join(dir, "out.bin"));
  assert.deepEqual(
    readdirSync(dir).filter((name) => name.includes(".tmp")),
    [],
  );
});

test("cancellation publishes nothing", () => {
  const dir = tmpdir();
  const store = trustingStore(dir, alice, "alice");
  const pkg = seal(dir, alice, bob.public, randomBytes(2 * CHUNK));
  const out = path.join(dir, "out.bin");

  class Cancelled extends Error {}
  assert.throws(
    () =>
      openFile({
        recipient: bob,
        contacts: store,
        packagePath: pkg,
        outputPath: out,
        overwrite: true,
        progress: (_bytes, chunks) => {
          if (chunks >= 1) throw new Cancelled("cancelled");
        },
      }),
    Cancelled,
  );
  assert.ok(!existsSync(out));
  assert.deepEqual(
    readdirSync(dir).filter((name) => name.includes(".tmp")),
    [],
  );
});

// ---- Numeric validation and bounds --------------------------------------

test("non-integer lengths are rejected, not coerced", () => {
  for (const bad of [Number.NaN, 0.5, 1.5, -1, Infinity, -Infinity, 2 ** 53]) {
    assert.throws(() => requireIndex(bad, "test value"), LimitError);
  }
  assert.equal(requireIndex(0, "zero"), 0);
  assert.equal(requireIndex(7, "seven"), 7);
});

test("checked addition catches overflow", () => {
  assert.throws(() => checkedAdd(2 ** 52, 2 ** 52, 2 ** 53 - 1), LimitError);
  assert.equal(checkedAdd(1, 2), 3);
});

test("checked multiplication catches overflow", () => {
  assert.throws(() => checkedMul(2 ** 30, 2 ** 30, 2 ** 53 - 1), LimitError);
});

test("the reader rejects trailing bytes", () => {
  const reader = new ByteReader(Buffer.from("abcd"), "thing");
  reader.take(2, "half");
  assert.throws(() => reader.finish(), FormatError);
});

test("the reader rejects overruns", () => {
  const reader = new ByteReader(Buffer.from("ab"), "thing");
  assert.throws(() => reader.take(3, "too much"), FormatError);
});

test("a package that is too small is rejected", () => {
  const dir = tmpdir();
  const store = new ContactStore(path.join(dir, "contacts"));
  const pkg = path.join(dir, "tiny.albpkg");
  writeFileSync(pkg, Buffer.alloc(100));
  assert.throws(() => open(pkg, bob, store, path.join(dir, "out.bin")), FormatError);
});

// ---- Key derivation binding ---------------------------------------------

test("chunk keys are distinct per index", () => {
  const master = Buffer.alloc(32, 1);
  const hd = Buffer.alloc(32, 2);
  const keys = new Set<string>();
  for (let i = 0; i < 64; i++) {
    keys.add(deriveChunkKey(master, hd, i).toString("hex"));
  }
  assert.equal(keys.size, 64);
});

test("keys are bound to the header digest", () => {
  const ss = Buffer.alloc(32, 3);
  assert.notDeepEqual(
    deriveMaster(ss, Buffer.alloc(32, 0)),
    deriveMaster(ss, Buffer.alloc(32, 1)),
  );
});

test("the completion key differs from every chunk key", () => {
  const master = Buffer.alloc(32, 4);
  const hd = Buffer.alloc(32, 5);
  const done = deriveCompletionKey(master, hd);
  for (let i = 0; i < 16; i++) {
    assert.notDeepEqual(done, deriveChunkKey(master, hd, i));
  }
});

test("chunk index bounds are enforced", () => {
  const master = Buffer.alloc(32);
  const hd = Buffer.alloc(32);
  assert.throws(() => deriveChunkKey(master, hd, -1), LimitError);
  assert.throws(() => deriveChunkKey(master, hd, suite.MAX_CHUNKS), LimitError);
});

// ---- No secret leakage ---------------------------------------------------

test("errors never contain key material", () => {
  const dir = tmpdir();
  const store = new ContactStore(path.join(dir, "contacts"));
  const pkg = seal(dir, alice, bob.public, Buffer.from("secret plaintext contents"));
  try {
    open(pkg, bob, store, path.join(dir, "out.bin"));
    assert.fail("expected a trust failure");
  } catch (error) {
    const text = String(error);
    assert.ok(!text.includes("secret plaintext"));
    assert.ok(!text.includes(PASSPHRASE));
  }
});

test("the CLI has no passphrase argument", async () => {
  const { parseArgs, USAGE } = await import("../src/cli.ts");
  assert.ok(!USAGE.includes("--passphrase "));
  assert.ok(USAGE.includes("--passphrase-fd"));
  assert.throws(() => parseArgs(["--passphrase", "hunter2", "show-identity"]), FormatError);
});

// ---- No C512 in the product path ----------------------------------------

test("the product does not reference C512", () => {
  const srcDir = path.join(import.meta.dirname, "..", "src");
  for (const name of readdirSync(srcDir)) {
    if (!name.endsWith(".ts")) continue;
    const text = readFileSync(path.join(srcDir, name), "utf8")
      .toLowerCase()
      .replaceAll("alb_c512", "");
    assert.ok(!text.includes("c512"), `${name} mentions C512`);
  }
});
