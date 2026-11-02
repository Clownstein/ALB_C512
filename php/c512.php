<?php
/**
 * ALB_C512 (C512) v2.0 — Reference Implementation in PHP 8.2+
 *
 * A sponge-based authenticated encryption algorithm with:
 *   - 512-bit key, 256-bit nonce, 256-bit tag
 *   - 1024-bit internal state (32 lanes × 32 bits)
 *   - Keccak-chi S-box + NTT lattice mixing
 *   - Dual-phase rounds: a=24 (init/finalize), b=12 (data blocks)
 *
 * Usage:
 *   $cipher = new C512Cipher();
 *   $ct = $cipher->encrypt($key, $nonce, $aad, $plaintext);
 *   $pt = $cipher->decrypt($key, $nonce, $aad, $ct);
 */

declare(strict_types=1);

class C512Cipher
{
    // ── Constants ──────────────────────────────────────────────────────────

    public const VERSION = '2.0';

    public const KEY_SIZE = 64;
    public const NONCE_SIZE = 32;
    public const TAG_SIZE = 32;
    public const STATE_SIZE = 128;
    public const RATE_SIZE = 64;
    public const LANES = 32;
    public const HALF_LANES = 16;
    public const ROUNDS_A = 24;
    public const ROUNDS_B = 12;
    public const KDF_ROUNDS = 4;

    private const MASK32 = 0xFFFFFFFF;

    /** Round constants from fractional bits of sqrt(2) and sqrt(3), split into 32-bit lanes. */
    private const ROUND_CONSTANTS_LO = [
        0xF3BCC908, 0x84CAA73B, 0xFE94F82B, 0x5F1D36F1,
        0xADE682D1, 0x2B3E6C1F, 0xFB41BD6B, 0x137E2179,
        0xD728AE22, 0x23EF65CD, 0xEC4D3B2F, 0x8189DBBC,
        0xF348B538, 0xB605D019, 0xAF194F9B, 0xDA6D8118,
        0xA3030242, 0x45706FBE, 0x4EE4B28C, 0xD5FFB4E2,
        0xF27B896F, 0x3B1696B1, 0x25C71235, 0xCF692694,
    ];

    private const ROUND_CONSTANTS_HI = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    ];

    /** NTT butterfly twiddle factors */
    private const OMEGA = [
        0x00000001, 0x6A09E667, 0xBB67AE85, 0x3C6EF372,
        0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19, 0x428A2F98, 0x71374491, 0xB5C0FBCF,
        0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4,
    ];

    public function __construct() {
        if (PHP_INT_SIZE !== 8 || getenv('ALB_C512_EXPERIMENTAL') !== '1') {
            throw new \RuntimeException('C512 requires 64-bit PHP and explicit ALB_C512_EXPERIMENTAL=1; research only');
        }
    }

    private function mul32(int $a, int $b): int {
        $lo = ($a & 65535) * ($b & 65535);
        $hi = ((($a >> 16) * ($b & 65535)) + (($b >> 16) * ($a & 65535))) & 65535;
        return ($lo + ($hi << 16)) & self::MASK32;
    }

    // ── State conversion ───────────────────────────────────────────────────

    /**
     * Convert 128-byte string to array of 32 uint32 lanes (little-endian).
     * @return int[]
     */
    private function stateFromBytes(string $b): array
    {
        if (strlen($b) !== self::STATE_SIZE) {
            throw new \InvalidArgumentException('C512: state must be 128 bytes');
        }
        $state = array_values(unpack('V32', $b));
        return $state;
    }

    /**
     * Convert 32 uint32 lanes to 128-byte string.
     * @param int[] $state
     */
    private function stateToBytes(array $state): string
    {
        $args = '';
        foreach ($state as $v) {
            $args .= pack('V', $v & self::MASK32);
        }
        return $args;
    }

    // ── Layer 1: Round Constants ───────────────────────────────────────────

    /** @param int[] $state */
    private function applyRoundConstant(array &$state, int $roundIdx): void
    {
        $idx = $roundIdx % 24;
        $state[16] = ($state[16] ^ self::ROUND_CONSTANTS_LO[$idx]) & self::MASK32;
        $state[17] = ($state[17] ^ self::ROUND_CONSTANTS_HI[$idx]) & self::MASK32;
    }

    // ── Layer 1b: Theta diffusion ──────────────────────────────────────────

    private const ROTATION_OFFSETS = [
        0, 1, 3, 6, 10, 15, 21, 28,
        2, 5, 9, 14, 20, 27, 3, 12,
        4, 8, 13, 19, 26, 1, 7, 16,
        11, 18, 25, 31, 17, 24, 30, 22,
    ];

    private function rotl32(int $x, int $n): int
    {
        $n &= 31;
        if ($n === 0) {
            return $x & self::MASK32;
        }
        return (($x << $n) | (($x >> (32 - $n)) & ((1 << $n) - 1))) & self::MASK32;
    }

    /** @param int[] $state */
    private function applyTheta(array &$state): void
    {
        $parity = array_fill(0, 32, 0);
        for ($i = 0; $i < 32; $i++) {
            $parity[$i] = (
                $state[($i + 32 - 5) % 32] ^
                $this->rotl32($state[($i + 5) % 32], 7) ^
                $state[($i + 32 - 13) % 32] ^
                $this->rotl32($state[($i + 13) % 32], 19)
            ) & self::MASK32;
        }
        for ($i = 0; $i < 32; $i++) {
            $state[$i] = ($state[$i] ^ $parity[$i]) & self::MASK32;
        }
        for ($i = 0; $i < 32; $i++) {
            $state[$i] = $this->rotl32($state[$i], self::ROTATION_OFFSETS[$i]);
        }
    }

    // ── Layer 2: Chi S-box ─────────────────────────────────────────────────

    /** @param int[] $state */
    private function applyChi(array &$state): void
    {
        $temp = $state;
        for ($i = 0; $i < 32; $i++) {
            $state[$i] = ($temp[$i] ^ ((~$temp[($i + 1) % 32]) & $temp[($i + 2) % 32])) & self::MASK32;
        }
    }

    // ── Layer 3: NTT Butterfly ─────────────────────────────────────────────

    /** @param int[] $state */
    private function nttButterflyHalf(array &$state, int $offset): void
    {
        $step = 8;
        while ($step >= 1) {
            $group = 0;
            while ($group < 16) {
                for ($j = 0; $j < $step; $j++) {
                    $idx1 = $offset + $group + $j;
                    $idx2 = $offset + $group + $j + $step;
                    $omegaIdx = ($j * intdiv(16, $step * 2)) % 16;
                    $temp = $this->mul32($state[$idx2], self::OMEGA[$omegaIdx]);
                    $state[$idx2] = ($state[$idx1] - $temp) & self::MASK32;
                    $state[$idx1] = ($state[$idx1] + $temp) & self::MASK32;
                }
                $group += $step * 2;
            }
            $step = intdiv($step, 2);
        }
    }

    /** @param int[] $state */
    private function applyNttButterfly(array &$state): void
    {
        $this->nttButterflyHalf($state, 0);
        $this->nttButterflyHalf($state, 16);
        // Bidirectional cross-mix
        for ($i = 0; $i < 16; $i++) {
            $a = $state[$i];
            $b = $state[16 + $i];
            $state[$i] = ($a ^ $this->rotl32($b, 11)) & self::MASK32;
            $state[16 + $i] = ($b ^ $this->rotl32($a, 23)) & self::MASK32;
        }
    }

    // ── Round Key Injection ────────────────────────────────────────────────

    /** @param int[] $state @param int[] $roundKey */
    private function applyRoundKey(array &$state, array $roundKey): void
    {
        for ($i = 0; $i < self::LANES; $i++) {
            $state[$i] = ($state[$i] ^ $roundKey[$i]) & self::MASK32;
        }
    }

    // ── Permutation ────────────────────────────────────────────────────────

    /** @param int[] $state @param int[][] $roundKeys */
    private function permutation(array &$state, int $rounds, array $roundKeys): void
    {
        $numKeys = count($roundKeys);
        for ($i = 0; $i < $rounds; $i++) {
            $this->applyRoundConstant($state, $i);
            $this->applyTheta($state);
            $this->applyChi($state);
            $this->applyNttButterfly($state);
            $this->applyRoundKey($state, $roundKeys[$i % $numKeys]);
        }
    }

    /** @param int[] $state */
    private function bootstrapPermutation(array &$state, int $rounds): void
    {
        for ($i = 0; $i < $rounds; $i++) {
            $this->applyRoundConstant($state, $i);
            $this->applyTheta($state);
            $this->applyChi($state);
            $this->applyNttButterfly($state);
        }
    }

    // ── Key Schedule ───────────────────────────────────────────────────────

    /**
     * Derive 24 round keys from the 64-byte master key.
     * @return int[][] Array of 24 round keys (each is int[32])
     */
    public function keySchedule(string $masterKey): array
    {
        if (strlen($masterKey) !== self::KEY_SIZE) {
            throw new \InvalidArgumentException('C512: key must be 64 bytes');
        }
        $revKey = strrev($masterKey);
        $combined = $masterKey . $revKey;
        $c = $this->stateFromBytes($combined);

        $roundKeys = [];
        for ($r = 0; $r < 24; $r++) {
            $this->bootstrapPermutation($c, self::KDF_ROUNDS);
            $roundKeys[] = $c;
            $c[0] = ($c[0] ^ ($r & self::MASK32)) & self::MASK32;
            $c[1] = ($c[1] ^ 0x43353230) & self::MASK32;
        }
        return $roundKeys;
    }

    // ── State Initialization ───────────────────────────────────────────────

    /** @return int[] */
    private function initState(string $key, string $nonce): array
    {
        if (strlen($key) !== self::KEY_SIZE) {
            throw new \InvalidArgumentException('C512: key must be 64 bytes');
        }
        if (strlen($nonce) !== self::NONCE_SIZE) {
            throw new \InvalidArgumentException('C512: nonce must be 32 bytes');
        }
        // IV(8) || Key(64) || Nonce(32) || Zeros(24) = 128 bytes
        $iv = pack('V2', 0x00000002, 0x80500C18);
        $initBytes = $iv . $key . $nonce . str_repeat("\x00", 24);
        if (strlen($initBytes) !== self::STATE_SIZE) {
            throw new \InvalidArgumentException('C512: state must be 128 bytes');
        }
        return $this->stateFromBytes($initBytes);
    }

    // ── Padding ────────────────────────────────────────────────────────────

    private function pad(string $data, int $blockSize): string
    {
        $padLen = $blockSize - (strlen($data) % $blockSize);
        if ($padLen === 0) {
            $padLen = $blockSize;
        }
        return $data . "\x80" . str_repeat("\x00", $padLen - 1);
    }

    // ── XOR helpers ────────────────────────────────────────────────────────

    /** @param int[] $state */
    private function xorBlockIntoState(array &$state, string $block, int $offset): void
    {
        for ($i = 0; $i < 16; $i++) {
            $v = unpack('V', substr($block, $offset + $i * 4, 4))[1];
            $state[$i] = ($state[$i] ^ $v) & self::MASK32;
        }
    }

    /** @param int[] $state */
    private function extractKeystream(array $state, int $length): string
    {
        $ks = '';
        for ($i = 0; $i < 16; $i++) {
            $ks .= pack('V', $state[$i] & self::MASK32);
        }
        return substr($ks, 0, $length);
    }

    // ── Encrypt ────────────────────────────────────────────────────────────

    public function encrypt(string $key, string $nonce, string $aad, string $plaintext): string
    {
        if (strlen($key) !== self::KEY_SIZE) {
            throw new \InvalidArgumentException('C512: key must be 64 bytes');
        }
        if (strlen($nonce) !== self::NONCE_SIZE) {
            throw new \InvalidArgumentException('C512: nonce must be 32 bytes');
        }

        $roundKeys = $this->keySchedule($key);
        $state = $this->initState($key, $nonce);
        $this->permutation($state, self::ROUNDS_A, $roundKeys);

        // Absorb AAD
        if (strlen($aad) > 0) {
            $aadPadded = $this->pad($aad, self::RATE_SIZE);
            $blocks = strlen($aadPadded) / self::RATE_SIZE;
            for ($i = 0; $i < $blocks; $i++) {
                $this->xorBlockIntoState($state, $aadPadded, $i * self::RATE_SIZE);
                $this->permutation($state, self::ROUNDS_B, $roundKeys);
            }
        }

        // Domain separation
        $state[31] = ($state[31] ^ 0x00000002) & self::MASK32;

        // Absorb plaintext / emit ciphertext
        $ciphertext = '';
        $ptLen = strlen($plaintext);
        $fullBlocks = intdiv($ptLen, self::RATE_SIZE);
        $remaining = $ptLen % self::RATE_SIZE;

        // Process full blocks
        for ($i = 0; $i < $fullBlocks; $i++) {
            $off = $i * self::RATE_SIZE;
            $keystream = $this->extractKeystream($state, self::RATE_SIZE);
            for ($j = 0; $j < self::RATE_SIZE; $j++) {
                $ciphertext .= chr(ord($keystream[$j]) ^ ord($plaintext[$off + $j]));
            }
            $absorb = substr($plaintext, $off, self::RATE_SIZE);
            $absorb .= str_repeat("\x00", self::RATE_SIZE - strlen($absorb));
            $this->xorBlockIntoState($state, $absorb, 0);
            $this->permutation($state, self::ROUNDS_B, $roundKeys);
        }

        // Final block: partial plaintext + 0x80 padding
        $lastBlock = str_repeat("\x00", self::RATE_SIZE);
        if ($remaining > 0) {
            $off = $fullBlocks * self::RATE_SIZE;
            $keystream = $this->extractKeystream($state, $remaining);
            for ($j = 0; $j < $remaining; $j++) {
                $ciphertext .= chr(ord($keystream[$j]) ^ ord($plaintext[$off + $j]));
                $lastBlock[$j] = $plaintext[$off + $j];
            }
        }
        $lastBlock[$remaining] = "\x80";
        $this->xorBlockIntoState($state, $lastBlock, 0);
        $this->permutation($state, self::ROUNDS_B, $roundKeys);

        // Finalize
        $this->permutation($state, self::ROUNDS_A, $roundKeys);

        // Tag domain separator + squeeze
        $state[31] = ($state[31] ^ 0x54414732) & self::MASK32;
        $this->permutation($state, self::ROUNDS_A, $roundKeys);
        $tag = '';
        for ($i = 0; $i < 8; $i++) {
            $tag .= pack('V', $state[$i] & self::MASK32);
        }

        return $ciphertext . $tag;
    }

    // ── Decrypt ────────────────────────────────────────────────────────────

    public function decrypt(string $key, string $nonce, string $aad, string $data): string
    {
        if (strlen($key) !== self::KEY_SIZE) {
            throw new \InvalidArgumentException('C512: key must be 64 bytes');
        }
        if (strlen($nonce) !== self::NONCE_SIZE) {
            throw new \InvalidArgumentException('C512: nonce must be 32 bytes');
        }

        if (strlen($data) < self::TAG_SIZE) {
            throw new \RuntimeException('C512: data too short');
        }

        $ctLen = strlen($data) - self::TAG_SIZE;
        $ciphertext = substr($data, 0, $ctLen);
        $tag = substr($data, $ctLen, self::TAG_SIZE);

        $roundKeys = $this->keySchedule($key);
        $state = $this->initState($key, $nonce);
        $this->permutation($state, self::ROUNDS_A, $roundKeys);

        // Absorb AAD
        if (strlen($aad) > 0) {
            $aadPadded = $this->pad($aad, self::RATE_SIZE);
            $blocks = strlen($aadPadded) / self::RATE_SIZE;
            for ($i = 0; $i < $blocks; $i++) {
                $this->xorBlockIntoState($state, $aadPadded, $i * self::RATE_SIZE);
                $this->permutation($state, self::ROUNDS_B, $roundKeys);
            }
        }

        // Domain separation
        $state[31] = ($state[31] ^ 0x00000002) & self::MASK32;

        // Decrypt blocks
        $plaintext = '';
        $fullBlocks = intdiv($ctLen, self::RATE_SIZE);
        $remaining = $ctLen % self::RATE_SIZE;

        // Process full blocks
        for ($i = 0; $i < $fullBlocks; $i++) {
            $off = $i * self::RATE_SIZE;
            $keystream = $this->extractKeystream($state, self::RATE_SIZE);
            $absorb = str_repeat("\x00", self::RATE_SIZE);
            for ($j = 0; $j < self::RATE_SIZE; $j++) {
                $pb = chr(ord($keystream[$j]) ^ ord($ciphertext[$off + $j]));
                $plaintext .= $pb;
                $absorb[$j] = $pb;
            }
            $this->xorBlockIntoState($state, $absorb, 0);
            $this->permutation($state, self::ROUNDS_B, $roundKeys);
        }

        // Final block: partial recovered plaintext + 0x80 padding
        $lastBlock = str_repeat("\x00", self::RATE_SIZE);
        if ($remaining > 0) {
            $off = $fullBlocks * self::RATE_SIZE;
            $keystream = $this->extractKeystream($state, $remaining);
            for ($j = 0; $j < $remaining; $j++) {
                $pb = chr(ord($keystream[$j]) ^ ord($ciphertext[$off + $j]));
                $plaintext .= $pb;
                $lastBlock[$j] = $pb;
            }
        }
        $lastBlock[$remaining] = "\x80";
        $this->xorBlockIntoState($state, $lastBlock, 0);
        $this->permutation($state, self::ROUNDS_B, $roundKeys);

        // Finalize and verify
        $this->permutation($state, self::ROUNDS_A, $roundKeys);

        $state[31] = ($state[31] ^ 0x54414732) & self::MASK32;
        $this->permutation($state, self::ROUNDS_A, $roundKeys);
        $expectedTag = '';
        for ($i = 0; $i < 8; $i++) {
            $expectedTag .= pack('V', $state[$i] & self::MASK32);
        }

        if (!hash_equals($expectedTag, $tag)) {
            throw new \RuntimeException('C512: authentication failed — ciphertext tampered');
        }

        return $plaintext;
    }

    // ── Convenience wrappers ───────────────────────────────────────────────

    public function encryptWithNonce(string $key, string $aad, string $plaintext): string
    {
        $nonce = random_bytes(self::NONCE_SIZE);
        $inner = $this->encrypt($key, $nonce, $aad, $plaintext);
        return $nonce . $inner;
    }

    public function decryptWithNonce(string $key, string $aad, string $data): string
    {
        if (strlen($data) < self::NONCE_SIZE + self::TAG_SIZE) {
            throw new \RuntimeException('C512: data too short (missing nonce+tag)');
        }
        $nonce = substr($data, 0, self::NONCE_SIZE);
        $inner = substr($data, self::NONCE_SIZE);
        return $this->decrypt($key, $nonce, $aad, $inner);
    }

    // ── Self-test ──────────────────────────────────────────────────────────

    public static function selfTest(): bool
    {
        $cipher = new self();
        $key = implode('', array_map('chr', range(0, 63)));
        $nonce = implode('', array_map('chr', range(0, 31)));

        // Test 1: empty plaintext, empty AAD — round-trip
        $ct = $cipher->encrypt($key, $nonce, '', '');
        if (strlen($ct) !== self::TAG_SIZE) {
            throw new \RuntimeException('C512 self-test 1 failed: wrong ciphertext length');
        }
        $pt = $cipher->decrypt($key, $nonce, '', $ct);
        if ($pt !== '') {
            throw new \RuntimeException('C512 self-test 1 failed: decryption mismatch');
        }

        // Test 2: 64-byte plaintext with 64-byte AAD — round-trip
        $plaintext = str_repeat("\x55", 64);
        $aad = str_repeat("\xAA", 64);
        $ct = $cipher->encrypt($key, $nonce, $aad, $plaintext);
        if (strlen($ct) !== 64 + self::TAG_SIZE) {
            throw new \RuntimeException('C512 self-test 2 failed: wrong ciphertext length');
        }
        $pt = $cipher->decrypt($key, $nonce, $aad, $ct);
        if ($pt !== $plaintext) {
            throw new \RuntimeException('C512 self-test 2 failed: decryption mismatch');
        }

        // Test 3: 37-byte non-aligned plaintext — round-trip
        $plaintext3 = 'Hello, ALB_C512 encryption test!!!!!' ;
        $plaintext3 = substr($plaintext3, 0, 37);
        $ct3 = $cipher->encrypt($key, $nonce, '', $plaintext3);
        if (strlen($ct3) !== 37 + self::TAG_SIZE) {
            throw new \RuntimeException('C512 self-test 3 failed: wrong ciphertext length');
        }
        $pt3 = $cipher->decrypt($key, $nonce, '', $ct3);
        if ($pt3 !== $plaintext3) {
            throw new \RuntimeException('C512 self-test 3 failed: non-aligned round-trip mismatch');
        }

        // Test 4: single byte — round-trip
        $ct4 = $cipher->encrypt($key, $nonce, '', "\xFF");
        if (strlen($ct4) !== 1 + self::TAG_SIZE) {
            throw new \RuntimeException('C512 self-test 4 failed: wrong ciphertext length');
        }
        $pt4 = $cipher->decrypt($key, $nonce, '', $ct4);
        if ($pt4 !== "\xFF") {
            throw new \RuntimeException('C512 self-test 4 failed: single byte round-trip mismatch');
        }

        // Test 5: tampered ciphertext must fail authentication
        $tampered = $ct;
        $tampered[0] = chr(ord($tampered[0]) ^ 0xFF);
        try {
            $cipher->decrypt($key, $nonce, $aad, $tampered);
            throw new \RuntimeException('C512 self-test 5 failed: tampered ciphertext was not rejected');
        } catch (\RuntimeException $e) {
            if (strpos($e->getMessage(), 'self-test 5') !== false ||
                strpos($e->getMessage(), 'authentication failed') === false) {
                throw $e;
            }
        }

        // Test 6: convenience wrappers — round-trip
        $full = $cipher->encryptWithNonce($key, $aad, $plaintext);
        $pt6 = $cipher->decryptWithNonce($key, $aad, $full);
        if ($pt6 !== $plaintext) {
            throw new \RuntimeException('C512 self-test 6 failed: convenience wrapper mismatch');
        }

        return true;
    }
}

// ── CLI ────────────────────────────────────────────────────────────────────

if (php_sapi_name() === 'cli' && basename($argv[0] ?? '') === basename(__FILE__)) {
    if (($argv[1] ?? '') === 'test') {
        if (C512Cipher::selfTest()) {
            echo "All C512 self-tests PASSED.\n";
        }
        exit(0);
    }
    echo "ALB_C512 (C512) PHP Reference Implementation\n";
    echo "Usage: php c512.php test\n";
}
