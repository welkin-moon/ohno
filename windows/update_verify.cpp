#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <cstring>
#include "update_verify.hpp"
#pragma comment(lib, "bcrypt.lib")
namespace ohno {
namespace {
struct algorithm { BCRYPT_ALG_HANDLE value = nullptr; ~algorithm() { if (value) BCryptCloseAlgorithmProvider(value, 0); } };
struct key_handle { BCRYPT_KEY_HANDLE value = nullptr; ~key_handle() { if (value) BCryptDestroyKey(value); } };
std::vector<unsigned char> decode_hex(const std::string& input) {
    auto nibble = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    std::vector<unsigned char> output;
    for (std::size_t i = 0; i < input.size(); i += 2)
        output.push_back(static_cast<unsigned char>((nibble(input[i]) << 4) | nibble(input[i+1])));
    return output;
}
}
UpdateManifest verify_update_offer(const std::string& document, const std::string& pinned_public_key,
    std::uint64_t installed_sequence, std::uint64_t updater_version, std::uint64_t now) {
    const auto manifest = parse_update_manifest(document);
    if (!update_detail::lower_hex(pinned_public_key, 130) || pinned_public_key.substr(0, 2) != "04")
        throw std::runtime_error("invalid pinned release key");
    auto public_bytes = decode_hex(pinned_public_key);
    std::array<unsigned char, sizeof(BCRYPT_ECCKEY_BLOB) + 64> blob{};
    const BCRYPT_ECCKEY_BLOB header{BCRYPT_ECDSA_PUBLIC_P256_MAGIC, 32};
    std::memcpy(blob.data(), &header, sizeof(header));
    std::memcpy(blob.data() + sizeof(header), public_bytes.data() + 1, 64);
    algorithm ecdsa, sha256;
    key_handle key;
    if (BCryptOpenAlgorithmProvider(&ecdsa.value, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptImportKeyPair(ecdsa.value, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key.value,
            blob.data(), static_cast<ULONG>(blob.size()), 0) < 0 ||
        BCryptOpenAlgorithmProvider(&sha256.value, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        throw std::runtime_error("update signature verification unavailable");
    std::array<unsigned char, 32> hash{};
    auto transcript = update_signing_bytes(manifest);
    if (BCryptHash(sha256.value, nullptr, 0, reinterpret_cast<PUCHAR>(transcript.data()),
            static_cast<ULONG>(transcript.size()), hash.data(), static_cast<ULONG>(hash.size())) < 0)
        throw std::runtime_error("update signature hash failed");
    auto signature = decode_hex(manifest.signature);
    if (BCryptVerifySignature(key.value, nullptr, hash.data(), static_cast<ULONG>(hash.size()),
            signature.data(), static_cast<ULONG>(signature.size()), 0) < 0)
        throw std::runtime_error("update signature not trusted");
    require_new_update(manifest, installed_sequence, updater_version, now);
    return manifest;
}
}
