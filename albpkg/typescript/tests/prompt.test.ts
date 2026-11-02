import test from "node:test";
import assert from "node:assert/strict";
import { PassThrough, Writable } from "node:stream";
import { promptPassphrase, loadIdentity } from "../src/identity.ts";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LimitError } from "../src/errors.ts";

test("oversized identity is rejected before requesting a passphrase", async () => {
  const directory = mkdtempSync(join(tmpdir(), "albpkg-limit-"));
  try {
    const filename = join(directory, "identity");
    writeFileSync(filename, Buffer.alloc(65537));
    await assert.rejects(loadIdentity(filename, { passphraseProvider: () => {
      assert.fail("oversized identity requested a passphrase");
    } }), LimitError);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("passphrase prompt never writes input bytes to its output", async () => {
  const originalInput = Object.getOwnPropertyDescriptor(process, "stdin")!;
  const originalOutput = Object.getOwnPropertyDescriptor(process, "stderr")!;
  const input = new PassThrough() as PassThrough & { isTTY: boolean; setRawMode: () => void };
  input.isTTY = true;
  input.setRawMode = () => {};
  let emitted = "";
  const output = new Writable({ write(chunk, _encoding, done) { emitted += chunk.toString(); done(); } });
  Object.defineProperty(process, "stdin", { configurable: true, value: input });
  Object.defineProperty(process, "stderr", { configurable: true, value: output });
  try {
    const answer = promptPassphrase("Password");
    input.write("secret-test-marker\r");
    assert.equal(await answer, "secret-test-marker");
    assert.equal(emitted, "Password: \n");
  } finally {
    Object.defineProperty(process, "stdin", originalInput);
    Object.defineProperty(process, "stderr", originalOutput);
    input.destroy();
    output.destroy();
  }
});
