"""One-time source migration; refuses to change the algorithm or its vectors."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

def edit(name, transform):
    p = ROOT / name
    p.write_text(transform(p.read_text(encoding='utf-8-sig')), encoding='utf-8')

def python_harden(s):
    s = s.replace('    rev_key = master_key[::-1]', '    _require_experimental()\n    rev_key = master_key[::-1]')
    marker = '# ── Helpers '
    at = s.index(marker)
    s = s[:at] + '''# Research only. This gate is deliberately separate from package encryption.
MAX_RESEARCH_BYTES = 16 * 1024 * 1024

def _require_experimental():
    if os.environ.get("ALB_C512_EXPERIMENTAL") != "1":
        raise RuntimeError("C512 is broken research cryptography; explicitly set ALB_C512_EXPERIMENTAL=1 for experiments only")

def _bound(value, name="input"):
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(name + " must be bytes")
    if len(value) > MAX_RESEARCH_BYTES:
        raise ValueError(name + " exceeds the 16 MiB research limit")

''' + s[at:]
    # Apply bounds at actual entrypoints, preserving their docstrings.
    lines = s.splitlines(True)
    for i in range(len(lines)-1, -1, -1):
        line = lines[i]
        if re.match(r'def (encrypt|decrypt|xof|siv_encrypt|siv_decrypt)\(', line):
            j=i+1
            if lines[j].lstrip().startswith('"""'):
                if lines[j].count('"""') < 2:
                    j+=1
                    while '"""' not in lines[j]: j+=1
                j+=1
            names=[n for n in ['aad','plaintext','data','context'] if re.search(r'\b'+n+r':',line)]
            lines[j:j]=[f'    _bound({n}, "{n}")\n' for n in names]
    s=''.join(lines)
    s=s.replace('if output_length < 0:', 'if type(output_length) is not int or not 0 <= output_length <= MAX_RESEARCH_BYTES:')
    s=s.replace('        self._buffer.extend(plaintext_chunk)', '        _bound(plaintext_chunk)\n        if len(self._ciphertext) + len(self._buffer) + len(plaintext_chunk) > MAX_RESEARCH_BYTES:\n            self.close()\n            raise ValueError("research context limit exceeded")\n        self._buffer.extend(plaintext_chunk)')
    s=s.replace('        self._buffer.extend(ciphertext_chunk)', '        _bound(ciphertext_chunk)\n        if len(self._plaintext) + len(self._buffer) + len(ciphertext_chunk) > MAX_RESEARCH_BYTES:\n            self.close()\n            raise ValueError("research context limit exceeded")\n        self._buffer.extend(ciphertext_chunk)')
    s=s.replace('        while len(self._buffer) >= C512_RATE_SIZE:', '        cursor = 0\n        while len(self._buffer) - cursor >= C512_RATE_SIZE:')
    s=s.replace('bytes(self._buffer[:C512_RATE_SIZE])', 'bytes(self._buffer[cursor:cursor + C512_RATE_SIZE])')
    s=s.replace('            self._buffer = self._buffer[C512_RATE_SIZE:]', '            cursor += C512_RATE_SIZE')
    s=s.replace('        self._ciphertext.extend(ct_chunk)', '        del self._buffer[:cursor]\n        self._ciphertext.extend(ct_chunk)')
    s=s.replace('    def finalize(self, tag: bytes)', '        del self._buffer[:cursor]\n\n    def finalize(self, tag: bytes)')
    s=s.replace('        return bytes(self._ciphertext), tag', '        result = bytes(self._ciphertext), tag\n        self.close()\n        return result')
    s=s.replace('        if len(tag) != C512_TAG_SIZE:\n            raise', '        if len(tag) != C512_TAG_SIZE:\n            self.close()\n            raise')
    s=s.replace('        if not _hmac.compare_digest(expected_tag, tag):\n            raise', '        if not _hmac.compare_digest(expected_tag, tag):\n            self.close()\n            raise')
    s=s.replace('        return bytes(self._plaintext)', '        result = bytes(self._plaintext)\n        self.close()\n        return result')
    close='''    def close(self):
        self._finalized = True
        for name in ("_buffer", "_plaintext", "_ciphertext", "_state"):
            value = getattr(self, name, None)
            if value is not None:
                for i in range(len(value)): value[i] = 0
                value.clear()
        for row in self._round_keys:
            for i in range(len(row)): row[i] = 0
        self._round_keys.clear()

'''
    s=s.replace('    def update(self,', close+'    def update(self,')
    s=s.replace('        self._round_keys = key_schedule(key)', '        _bound(aad, "aad")\n        self._round_keys = key_schedule(key)')
    return s

edit('python/c512.py', python_harden)
edit('python/c512_lite.py', python_harden)

def php_harden(s):
    s=s.replace('($state[$idx2] * self::OMEGA[$omegaIdx]) & self::MASK32', '$this->mul32($state[$idx2], self::OMEGA[$omegaIdx])')
    pos=s.index('    // ── State conversion')
    s=s[:pos]+'''    public function __construct() {
        if (PHP_INT_SIZE !== 8 || getenv('ALB_C512_EXPERIMENTAL') !== '1') {
            throw new \\RuntimeException('C512 requires 64-bit PHP and explicit ALB_C512_EXPERIMENTAL=1; research only');
        }
    }

    private function mul32(int $a, int $b): int {
        $lo = ($a & 65535) * ($b & 65535);
        $hi = ((($a >> 16) * ($b & 65535)) + (($b >> 16) * ($a & 65535))) & 65535;
        return ($lo + ($hi << 16)) & self::MASK32;
    }

'''+s[pos:]
    return s
edit('php/c512.php',php_harden)

def ts_harden(s):
    s=s.replace('if (outputLength < 0)', 'if (!Number.isSafeInteger(outputLength) || outputLength < 0 || outputLength > 16777216)')
    s=s.replace('sivDv.setUint32(4, 0, true);','sivDv.setUint32(4, Math.floor(aad.length / 0x100000000), true);')
    s=s.replace('sivDv.setUint32(ptOffset + 4, 0, true);','sivDv.setUint32(ptOffset + 4, Math.floor(plaintext.length / 0x100000000), true);')
    s='''// Explicit research-only gate. Never imported by the package implementation.
let experimental = false;
export function enableExperimentalResearch(): void { experimental = true; }
function requireResearch(): void {
  if (!experimental) throw new Error("C512 is broken research cryptography; call enableExperimentalResearch() only for experiments");
}
'''+s
    s=re.sub(r'(function keySchedule\([^\n]+\{)',r'\1\n  requireResearch();',s)
    return s
edit('js/c512.ts',ts_harden)

def cpp_harden(s):
    s=s.replace('#pragma once','#pragma once\n#ifndef ALB_C512_EXPERIMENTAL\n#error "C512 is research only; define ALB_C512_EXPERIMENTAL explicitly"\n#endif')
    pos=s.index('// ── State conversion')
    s=s[:pos]+'''inline std::uint32_t load_le32(const std::uint8_t* p) {
    return std::uint32_t(p[0]) | (std::uint32_t(p[1]) << 8) | (std::uint32_t(p[2]) << 16) | (std::uint32_t(p[3]) << 24);
}
inline void store_le(std::uint8_t* p, std::uint64_t v, std::size_t n) {
    for (std::size_t i=0; i<n; ++i) p[i] = static_cast<std::uint8_t>(v >> (8*i));
}
'''+s[pos:]
    pairs={
      'std::memcpy(&state[i], b + i * 4, 4);':'state[i] = load_le32(b + i * 4);',
      'std::memcpy(b + i * 4, &state[i], 4);':'store_le(b + i * 4, state[i], 4);',
      'std::memcpy(init_bytes.data(), &iv, 8);':'store_le(init_bytes.data(), iv, 8);',
      'std::memcpy(&v, block + offset + i * 4, 4);':'v = load_le32(block + offset + i * 4);',
      'std::memcpy(out + i * 4, &state[i], bytes_to_copy);':'store_le(out + i * 4, state[i], bytes_to_copy);',
      'std::memcpy(&tag[i * 4], &state[i], 4);':'store_le(&tag[i * 4], state[i], 4);',
      'std::memcpy(&expected_tag[i * 4], &state[i], 4);':'store_le(&expected_tag[i * 4], state[i], 4);',
      'std::memcpy(&state[i], key.data() + i * 4, 4);':'state[i] = load_le32(key.data() + i * 4);',
      'std::memcpy(siv_input.data(), &al, 8);':'store_le(siv_input.data(), al, 8);',
      'std::memcpy(plbuf, &pl, 8);':'store_le(plbuf, pl, 8);',
      'std::memcpy(&nonce[i*4], &state[i], 4);':'store_le(&nonce[i*4], state[i], 4);',
    }
    for a,b in pairs.items(): s=s.replace(a,b)
    s=s.replace('    auto pad_len = block_size', '    if (block_size == 0 || block_size > 128 || len > 16777216 || (len && !data)) throw std::invalid_argument("invalid research input");\n    auto pad_len = block_size')
    s=s.replace('    auto num_keys = round_keys.size();','    auto num_keys = round_keys.size();\n    if (!num_keys || rounds > 24) throw std::invalid_argument("invalid permutation parameters");')
    return s
edit('cpp/c512.hpp',cpp_harden)

def other_gate(s, language):
    if language=='rust':
        return s.replace('    let mut rev_key = *master_key;', '    assert!(std::env::var("ALB_C512_EXPERIMENTAL").as_deref() == Ok("1"), "C512 is research only; set ALB_C512_EXPERIMENTAL=1 explicitly");\n    let mut rev_key = *master_key;')
    if language=='pascal':
        return s.replace('  if Length(MasterKey) <> C512_KEY_SIZE then', "  if GetEnvironmentVariable('ALB_C512_EXPERIMENTAL') <> '1' then\n    raise Exception.Create('C512 is research only; explicit experimental opt-in required');\n  if Length(MasterKey) <> C512_KEY_SIZE then").replace('  for I := 0 to Rounds - 1 do', "  if (Rounds < 0) or (Rounds > 24) then\n    raise Exception.Create('Invalid round count');\n  for I := 0 to Rounds - 1 do",1).replace('    ApplyRoundKeyInjection(State, RoundKeys[I mod Length(RoundKeys)]);', "    if Length(RoundKeys) = 0 then raise Exception.Create('Empty round keys');\n    ApplyRoundKeyInjection(State, RoundKeys[I mod Length(RoundKeys)]);")
    if language=='go':
        s=s.replace('import (','import (\n "os"')
        s=s.replace('if len(key) != KeySize {','if os.Getenv("ALB_C512_EXPERIMENTAL") != "1" { return nil, fmt.Errorf("C512 is research only; explicit experimental opt-in required") }\n if len(key) != KeySize {')
        return s
edit('rust/c512.rs',lambda s:other_gate(s,'rust'))
edit('go/c512.go',lambda s:other_gate(s,'go'))
edit('pascal/uC512Cipher.pas',lambda s:other_gate(s,'pascal'))

edit('tools/test_vectors_v2_verify.py',lambda s:s.replace('Cross-Language Test Vector Verification Harness','Python Test Vector Verification Harness').replace('            print(f"\\n  Lite vectors not found at {lite_path}")','            print(f"\\n  Lite vectors not found at {lite_path}")\n            failed += 1'))
edit('tools/c512_crack_attempt.py',lambda s:s.replace('RESULT: No vulnerabilities detected.','RESULT: Selected smoke checks passed; this is not a security assessment.').replace('The cipher appears resistant to all tested attacks.','C512 has known structural defects and must not protect real data.'))
