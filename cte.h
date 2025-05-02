#ifndef CTE_H
#define CTE_H

#include <stdlea.h>

// CTE Version
#define CTE_VERSION_BYTE 0xF1 // Minimal CTE 0xF version 0x01

// Max Transaction Size
#define CTE_MAX_TRANSACTION_SIZE 1232

// Field Tag Identifiers (Top 2 bits)
#define CTE_TAG_PUBLIC_KEY_LIST 0x00 // 00xxxxxx
#define CTE_TAG_SIGNATURE_LIST 0x40  // 01xxxxxx
#define CTE_TAG_IXDATA_FIELD 0x80    // 10xxxxxx
#define CTE_TAG_COMMAND_DATA 0xC0    // 11xxxxxx
#define CTE_TAG_MASK 0xC0            // Mask to extract tag

// --- Public Key List (Tag 00) / Signature List (Tag 01) ---
// Crypto Type Codes (Bits 1-0 in Header) - LIP-0002
#define CTE_CRYPTO_TYPE_ED25519 0x00      // 00
#define CTE_CRYPTO_TYPE_SLH_DSA_128F 0x01 // 01
#define CTE_CRYPTO_TYPE_SLH_DSA_192F 0x02 // 10
#define CTE_CRYPTO_TYPE_SLH_DSA_256F 0x03 // 11
#define CTE_CRYPTO_TYPE_MASK 0x03         // Mask for Type Code TT

// Key/Signature Sizes based on Type Code - LIP-0002
#define CTE_PUBKEY_SIZE_ED25519 32
#define CTE_PUBKEY_SIZE_SLH_128F 32
#define CTE_PUBKEY_SIZE_SLH_192F 48
#define CTE_PUBKEY_SIZE_SLH_256F 64

#define CTE_SIGNATURE_SIZE_ED25519 64
#define CTE_SIGNATURE_HASH_SIZE_PQC 32 // BLAKE3 hash size for SLH-DSA variants

// Max list length (Bits 5-2 in Header)
#define CTE_LIST_MAX_LEN 15

// --- IxData Field (Tag 10) ---
// Sub-Type Codes (Bits 1-0 in Header) - LIP-0001
#define CTE_IXDATA_SUBTYPE_LEGACY_INDEX 0x00 // 00
#define CTE_IXDATA_SUBTYPE_VARINT 0x01       // 01
#define CTE_IXDATA_SUBTYPE_FIXED 0x02        // 10
#define CTE_IXDATA_SUBTYPE_CONSTANT 0x03     // 11
#define CTE_IXDATA_SUBTYPE_MASK 0x03         // Mask for Sub-Type SS

// Varint Encoding Scheme Codes (Bits 5-2 in Header, SS=01) - LIP-0001
#define CTE_IXDATA_VARINT_ENC_ZERO 0x00    // 0000 -> Value 0
#define CTE_IXDATA_VARINT_ENC_ULEB128 0x01 // 0001 -> ULEB128 follows
#define CTE_IXDATA_VARINT_ENC_SLEB128 0x02 // 0010 -> SLEB128 follows
// 0x03 - 0x0F are Reserved

// Fixed Data Type Codes (Bits 5-2 in Header, SS=10) - LIP-0001
#define CTE_IXDATA_FIXED_TYPE_INT8 0x00    // 0000 -> int8_t (1 byte)
#define CTE_IXDATA_FIXED_TYPE_INT16 0x01   // 0001 -> int16_t (2 bytes)
#define CTE_IXDATA_FIXED_TYPE_INT32 0x02   // 0010 -> int32_t (4 bytes)
#define CTE_IXDATA_FIXED_TYPE_INT64 0x03   // 0011 -> int64_t (8 bytes)
#define CTE_IXDATA_FIXED_TYPE_UINT8 0x04   // 0100 -> uint8_t (1 byte)
#define CTE_IXDATA_FIXED_TYPE_UINT16 0x05  // 0101 -> uint16_t (2 bytes)
#define CTE_IXDATA_FIXED_TYPE_UINT32 0x06  // 0110 -> uint32_t (4 bytes)
#define CTE_IXDATA_FIXED_TYPE_UINT64 0x07  // 0111 -> uint64_t (8 bytes)
#define CTE_IXDATA_FIXED_TYPE_FLOAT32 0x08 // 1000 -> float (4 bytes)
#define CTE_IXDATA_FIXED_TYPE_FLOAT64 0x09 // 1001 -> double (8 bytes)
// 0x0A - 0x0F are Reserved

// Constant Value Codes (Bits 5-2 in Header, SS=11) - LIP-0001
#define CTE_IXDATA_CONST_VAL_FALSE 0x00 // 0000 -> false
#define CTE_IXDATA_CONST_VAL_TRUE 0x01  // 0001 -> true
// 0x02 - 0x0F are Reserved

// Max legacy index value (Bits 5-2 in Header, SS=00)
#define CTE_LEGACY_INDEX_MAX_VALUE 15

// --- Command Data (Tag 11) ---
// Format Flag (Bit 5 in Header)
#define CTE_COMMAND_FORMAT_FLAG_MASK 0x20 // Mask for format flag
#define CTE_COMMAND_FORMAT_SHORT 0x00     // Bit 5 = 0
#define CTE_COMMAND_FORMAT_EXTENDED 0x20  // Bit 5 = 1

// Lengths
#define CTE_COMMAND_SHORT_MAX_LEN 31 // Max length for short format (5 bits)
#define CTE_COMMAND_EXTENDED_MIN_LEN 32
#define CTE_COMMAND_EXTENDED_MAX_LEN 1197 // Max practical length (11 bits: 3+8)

size_t get_public_key_size(uint8_t type_code);
size_t get_signature_item_size(uint8_t type_code);

#endif // CTE_H
