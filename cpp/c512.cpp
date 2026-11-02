/**
 * ALB_C512 (C512) v2.0 -- C++20 Test Runner & CLI
 *
 * Compile: g++ -std=c++20 -O2 -o c512_test c512.cpp
 * Run:     ./c512_test
 */

#include "c512.hpp"
#include <iostream>
#include <cassert>
#include <chrono>
#include <iomanip>
#include <string>

// -- Helpers ----------------------------------------------------------------

static std::string hex_encode(const std::vector<std::uint8_t>& data) {
    std::string result;
    result.reserve(data.size() * 2);
    for (auto b : data) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", b);
        result += buf;
    }
    return result;
}

static std::string hex_encode(const std::uint8_t* data, std::size_t len) {
    std::string result;
    result.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", data[i]);
        result += buf;
    }
    return result;
}

// -- Round-trip encrypt/decrypt tests ---------------------------------------

static void test_roundtrip_empty() {
    c512::Key key{};
    for (std::size_t i = 0; i < 64; ++i) key[i] = static_cast<std::uint8_t>(i);
    c512::Nonce nonce{};
    for (std::size_t i = 0; i < 32; ++i) nonce[i] = static_cast<std::uint8_t>(i);

    auto ct = c512::encrypt(key, nonce, nullptr, 0, nullptr, 0);
    assert(ct.size() == c512::TAG_SIZE);

    auto pt = c512::decrypt(key, nonce, nullptr, 0, ct.data(), ct.size());
    assert(pt.empty());

    std::cout << "  [PASS] Round-trip: empty plaintext, empty AAD\n";
}

static void test_roundtrip_64B_with_aad() {
    c512::Key key{};
    for (std::size_t i = 0; i < 64; ++i) key[i] = static_cast<std::uint8_t>(i);
    c512::Nonce nonce{};
    for (std::size_t i = 0; i < 32; ++i) nonce[i] = static_cast<std::uint8_t>(i);

    std::array<std::uint8_t, 64> aad{};
    std::fill(aad.begin(), aad.end(), 0xAA);
    std::array<std::uint8_t, 64> plaintext{};
    std::fill(plaintext.begin(), plaintext.end(), 0x55);

    auto ct = c512::encrypt(key, nonce, aad.data(), aad.size(),
                            plaintext.data(), plaintext.size());
    assert(ct.size() == plaintext.size() + c512::TAG_SIZE);

    auto recovered = c512::decrypt(key, nonce, aad.data(), aad.size(),
                                   ct.data(), ct.size());
    assert(recovered.size() == plaintext.size());
    assert(std::equal(recovered.begin(), recovered.end(), plaintext.begin()));

    std::cout << "  [PASS] Round-trip: 64B plaintext, 64B AAD\n";
}

static void test_roundtrip_37B_no_aad() {
    c512::Key key{};
    for (std::size_t i = 0; i < 64; ++i) key[i] = static_cast<std::uint8_t>(i);
    c512::Nonce nonce{};
    for (std::size_t i = 0; i < 32; ++i) nonce[i] = static_cast<std::uint8_t>(i);

    // "Hello, ALB_C512 encryption test!!!"
    const std::uint8_t plaintext[] = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x41,
        0x4c, 0x42, 0x5f, 0x43, 0x35, 0x31, 0x32, 0x20,
        0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69,
        0x6f, 0x6e, 0x20, 0x74, 0x65, 0x73, 0x74, 0x21,
        0x21, 0x21, 0x21, 0x21, 0x21
    };
    constexpr std::size_t pt_len = sizeof(plaintext);

    auto ct = c512::encrypt(key, nonce, nullptr, 0, plaintext, pt_len);
    assert(ct.size() == pt_len + c512::TAG_SIZE);

    auto recovered = c512::decrypt(key, nonce, nullptr, 0, ct.data(), ct.size());
    assert(recovered.size() == pt_len);
    assert(std::equal(recovered.begin(), recovered.end(), plaintext));

    std::cout << "  [PASS] Round-trip: 37B plaintext, no AAD\n";
}

static void test_roundtrip_single_byte() {
    c512::Key key{};
    for (std::size_t i = 0; i < 64; ++i) key[i] = static_cast<std::uint8_t>(i);
    c512::Nonce nonce{};
    for (std::size_t i = 0; i < 32; ++i) nonce[i] = static_cast<std::uint8_t>(i);

    std::uint8_t plaintext = 0xFF;

    auto ct = c512::encrypt(key, nonce, nullptr, 0, &plaintext, 1);
    assert(ct.size() == 1 + c512::TAG_SIZE);

    auto recovered = c512::decrypt(key, nonce, nullptr, 0, ct.data(), ct.size());
    assert(recovered.size() == 1);
    assert(recovered[0] == 0xFF);

    std::cout << "  [PASS] Round-trip: single byte\n";
}

// -- Tamper test ------------------------------------------------------------

static void test_tampered_ciphertext() {
    c512::Key key{};
    for (std::size_t i = 0; i < 64; ++i) key[i] = static_cast<std::uint8_t>(i);
    c512::Nonce nonce{};
    for (std::size_t i = 0; i < 32; ++i) nonce[i] = static_cast<std::uint8_t>(i);

    std::array<std::uint8_t, 64> plaintext{};
    std::fill(plaintext.begin(), plaintext.end(), 0x55);

    auto ct = c512::encrypt(key, nonce, nullptr, 0, plaintext.data(), plaintext.size());
    ct[0] ^= 0xFF;

    bool threw = false;
    try {
        c512::decrypt(key, nonce, nullptr, 0, ct.data(), ct.size());
    } catch (const std::runtime_error&) {
        threw = true;
    }
    assert(threw);

    std::cout << "  [PASS] Tampered ciphertext rejected\n";
}

// -- SIV round-trip test ----------------------------------------------------

static void test_siv_roundtrip() {
    c512::Key key{};
    for (std::size_t i = 0; i < 64; ++i) key[i] = static_cast<std::uint8_t>(i);

    std::array<std::uint8_t, 16> aad{};
    std::fill(aad.begin(), aad.end(), 0xBB);
    std::array<std::uint8_t, 48> plaintext{};
    std::fill(plaintext.begin(), plaintext.end(), 0x42);

    auto ct = c512::siv_encrypt(key, aad.data(), aad.size(),
                                plaintext.data(), plaintext.size());
    // SIV output = nonce(32) + ciphertext(48) + tag(32) = 112 bytes
    assert(ct.size() == c512::NONCE_SIZE + plaintext.size() + c512::TAG_SIZE);

    auto recovered = c512::siv_decrypt(key, aad.data(), aad.size(),
                                       ct.data(), ct.size());
    assert(recovered.size() == plaintext.size());
    assert(std::equal(recovered.begin(), recovered.end(), plaintext.begin()));

    // Verify tamper detection: flip a byte in the ciphertext portion
    ct[c512::NONCE_SIZE] ^= 0x01;
    bool threw = false;
    try {
        c512::siv_decrypt(key, aad.data(), aad.size(), ct.data(), ct.size());
    } catch (const std::runtime_error&) {
        threw = true;
    }
    assert(threw);

    std::cout << "  [PASS] SIV round-trip + tamper detection\n";
}

// -- XOF determinism test ---------------------------------------------------

static void test_xof_determinism() {
    c512::Key key{};
    for (std::size_t i = 0; i < 64; ++i) key[i] = static_cast<std::uint8_t>(i);

    const std::uint8_t ctx[] = "test-context";
    constexpr std::size_t ctx_len = sizeof(ctx) - 1;

    auto out1 = c512::xof_output(key, ctx, ctx_len, 128);
    auto out2 = c512::xof_output(key, ctx, ctx_len, 128);
    assert(out1.size() == 128);
    assert(out2.size() == 128);
    assert(out1 == out2);

    // Different context should produce different output
    const std::uint8_t ctx2[] = "other-context";
    auto out3 = c512::xof_output(key, ctx2, sizeof(ctx2) - 1, 128);
    assert(out3 != out1);

    // Different length should produce a prefix match for the common portion
    auto out_short = c512::xof_output(key, ctx, ctx_len, 64);
    assert(out_short.size() == 64);
    assert(std::equal(out_short.begin(), out_short.end(), out1.begin()));

    std::cout << "  [PASS] XOF determinism + context sensitivity\n";
}

// -- Benchmark --------------------------------------------------------------

static void benchmark() {
    c512::Key key{};
    for (std::size_t i = 0; i < 64; ++i) key[i] = static_cast<std::uint8_t>(i);
    c512::Nonce nonce{};
    for (std::size_t i = 0; i < 32; ++i) nonce[i] = static_cast<std::uint8_t>(i);

    constexpr std::size_t DATA_SIZE = 1024 * 1024;
    std::vector<std::uint8_t> data(DATA_SIZE, 0x42);

    auto start = std::chrono::high_resolution_clock::now();
    constexpr int ITERS = 10;
    for (int i = 0; i < ITERS; ++i) {
        auto ct = c512::encrypt(key, nonce, nullptr, 0, data.data(), data.size());
        (void)ct;
    }
    auto end = std::chrono::high_resolution_clock::now();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double mbps = (static_cast<double>(DATA_SIZE) * ITERS / (1024.0 * 1024.0))
                  / (static_cast<double>(ms) / 1000.0);

    std::cout << "\n  Benchmark: " << std::fixed << std::setprecision(2)
              << mbps << " MB/s (encrypt " << DATA_SIZE / 1024
              << " KB x " << ITERS << " iterations)\n";
}

// -- Main -------------------------------------------------------------------

int main() {
    std::cout << "ALB_C512 (C512) v2.0 C++20 Reference Implementation\n";
    std::cout << "Running tests...\n\n";

    test_roundtrip_empty();
    test_roundtrip_64B_with_aad();
    test_roundtrip_37B_no_aad();
    test_roundtrip_single_byte();
    test_tampered_ciphertext();
    test_siv_roundtrip();
    test_xof_determinism();

    std::cout << "\nAll v2.0 tests passed!\n";

    benchmark();

    return 0;
}
