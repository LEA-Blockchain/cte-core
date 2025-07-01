#ifndef CTE_H
#define CTE_H

#include <stdlea.h>

/**
 * @file cte.h
 * @brief Core definitions and constants for the Compact Transaction Encoding (CTE).
 *
 * This file defines the fundamental constants, tags, masks, and type codes
 * used throughout the CTE library, as specified in the CTE v1.0 and related
 * LIPs. It also declares utility functions for querying properties of CTE types.
 */

/**
 * @def CTE_VERSION_BYTE
 * @brief The required first byte of any valid CTE v1.0 transaction stream.
 *
 * The version byte is structured as `1111 0001`, where `1111` represents
 * the "Minimal CTE" format family and `0001` is version 1.
 */
#define CTE_VERSION_BYTE 0xF1

/**
 * @def CTE_MAX_TRANSACTION_SIZE
 * @brief The maximum permissible size in bytes for a single CTE transaction.
 */
#define CTE_MAX_TRANSACTION_SIZE 1232

/**
 * @name Field Tag Identifiers
 * @brief The 2-bit tags in the most significant bits of a field's header byte.
 * @{
 */
#define CTE_TAG_PUBLIC_KEY_LIST 0x00 /**< Tag for a Public Key List field (binary `00`). */
#define CTE_TAG_SIGNATURE_LIST 0x40  /**< Tag for a Signature List field (binary `01`). */
#define CTE_TAG_IXDATA_FIELD 0x80    /**< Tag for an IxData (Index/Extended Data) field (binary `10`). */
#define CTE_TAG_COMMAND_DATA 0xC0    /**< Tag for a Command Data field (binary `11`). */
#define CTE_TAG_MASK 0xC0            /**< Mask to extract the 2-bit tag from a header byte. */
/** @} */

/**
 * @name Crypto Type Codes
 * @brief Sub-type codes for Public Key and Signature Lists (LIP-0002).
 * These codes are stored in the lower 2 bits of the list's header byte.
 * @{
 */
#define CTE_CRYPTO_TYPE_ED25519 0x00      /**< Ed25519 signature scheme. */
#define CTE_CRYPTO_TYPE_SLH_DSA_128F 0x01 /**< SLH-DSA-128f (PQC) signature scheme. */
#define CTE_CRYPTO_TYPE_SLH_DSA_192F 0x02 /**< SLH-DSA-192f (PQC) signature scheme. */
#define CTE_CRYPTO_TYPE_SLH_DSA_256F 0x03 /**< SLH-DSA-256f (PQC) signature scheme. */
#define CTE_CRYPTO_TYPE_MASK 0x03         /**< Mask to extract the 2-bit crypto type from a header. */
/** @} */

/**
 * @name Cryptographic Item Sizes
 * @brief Defines the byte sizes for public keys and signatures for each crypto type.
 * @{
 */
#define CTE_PUBKEY_SIZE_ED25519 32      /**< Size of an Ed25519 public key. */
#define CTE_PUBKEY_SIZE_SLH_128F 32     /**< Size of an SLH-DSA-128f public key. */
#define CTE_PUBKEY_SIZE_SLH_192F 48     /**< Size of an SLH-DSA-192f public key. */
#define CTE_PUBKEY_SIZE_SLH_256F 64     /**< Size of an SLH-DSA-256f public key. */

#define CTE_SIGNATURE_SIZE_ED25519 64   /**< Size of an Ed25519 signature. */
#define CTE_SIGNATURE_HASH_SIZE_PQC 32  /**< For PQC schemes, lists contain a 32-byte hash (BLAKE3) instead of a full signature. */
/** @} */

/**
 * @def CTE_LIST_MAX_LEN
 * @brief The maximum number of items (keys or signatures) allowed in a list.
 * This is defined by the 4-bit length field (N) in the list header.
 */
#define CTE_LIST_MAX_LEN 15

/**
 * @name IxData Field Sub-Types
 * @brief Sub-type codes for the IxData field (Tag 10), stored in the lower 2 bits (LIP-0001).
 * @{
 */
#define CTE_IXDATA_SUBTYPE_LEGACY_INDEX 0x00 /**< Sub-type for a 4-bit legacy index reference. */
#define CTE_IXDATA_SUBTYPE_VARINT 0x01       /**< Sub-type for a variable-length integer. */
#define CTE_IXDATA_SUBTYPE_FIXED 0x02        /**< Sub-type for a standard fixed-size data type. */
#define CTE_IXDATA_SUBTYPE_CONSTANT 0x03     /**< Sub-type for a single-byte constant value (e.g., boolean). */
#define CTE_IXDATA_SUBTYPE_MASK 0x03         /**< Mask to extract the 2-bit IxData sub-type. */
/** @} */

/**
 * @name CTE Peek Type Identifiers
 * @brief Unique identifiers returned by `cte_decoder_peek_type`.
 *
 * These constants are API-level identifiers and are NOT part of the CTE wire
 * format. They provide an unambiguous way for a parser to identify the
 * specific type of an upcoming field with a single function call, allowing
 * the use of a simple `switch` statement. The identifiers are organized by
 * the field's 2-bit tag.
 * @{
 */
// Tag 00: Public Key Lists
#define CTE_PEEK_TYPE_PK_LIST_ED25519 0
#define CTE_PEEK_TYPE_PK_LIST_SLH_128F 1
#define CTE_PEEK_TYPE_PK_LIST_SLH_192F 2
#define CTE_PEEK_TYPE_PK_LIST_SLH_256F 3

// Tag 01: Signature Lists
#define CTE_PEEK_TYPE_SIG_LIST_ED25519 4
#define CTE_PEEK_TYPE_SIG_LIST_SLH_128F 5
#define CTE_PEEK_TYPE_SIG_LIST_SLH_192F 6
#define CTE_PEEK_TYPE_SIG_LIST_SLH_256F 7

// Tag 10: IxData Fields
#define CTE_PEEK_TYPE_IXDATA_LEGACY_INDEX 8
#define CTE_PEEK_TYPE_IXDATA_VARINT_ZERO 9
#define CTE_PEEK_TYPE_IXDATA_ULEB128 10
#define CTE_PEEK_TYPE_IXDATA_SLEB128 11
#define CTE_PEEK_TYPE_IXDATA_INT8 12
#define CTE_PEEK_TYPE_IXDATA_INT16 13
#define CTE_PEEK_TYPE_IXDATA_INT32 14
#define CTE_PEEK_TYPE_IXDATA_INT64 15
#define CTE_PEEK_TYPE_IXDATA_UINT8 16
#define CTE_PEEK_TYPE_IXDATA_UINT16 17
#define CTE_PEEK_TYPE_IXDATA_UINT32 18
#define CTE_PEEK_TYPE_IXDATA_UINT64 19
#define CTE_PEEK_TYPE_IXDATA_FLOAT32 20
#define CTE_PEEK_TYPE_IXDATA_FLOAT64 21
#define CTE_PEEK_TYPE_IXDATA_CONST_FALSE 22
#define CTE_PEEK_TYPE_IXDATA_CONST_TRUE 23

// Tag 11: Command Data
#define CTE_PEEK_TYPE_CMD_SHORT 24
#define CTE_PEEK_TYPE_CMD_EXTENDED 25
/** @} */



/**
 * @name IxData Varint Encoding Schemes
 * @brief Encoding scheme codes for the Varint sub-type (SS=01), stored in bits 5-2 (LIP-0001).
 * @{
 */
#define CTE_IXDATA_VARINT_ENC_ZERO 0x00    /**< Represents the integer value 0 directly in the header. */
#define CTE_IXDATA_VARINT_ENC_ULEB128 0x01 /**< Indicates the value is encoded as ULEB128 data following the header. */
#define CTE_IXDATA_VARINT_ENC_SLEB128 0x02 /**< Indicates the value is encoded as SLEB128 data following the header. */
/** @} */

/**
 * @name IxData Fixed Data Type Codes
 * @brief Type codes for the Fixed Data sub-type (SS=10), stored in bits 5-2 (LIP-0001).
 * @{
 */
#define CTE_IXDATA_FIXED_TYPE_INT8 0x00    /**< `int8_t` (1 byte). */
#define CTE_IXDATA_FIXED_TYPE_INT16 0x01   /**< `int16_t` (2 bytes). */
#define CTE_IXDATA_FIXED_TYPE_INT32 0x02   /**< `int32_t` (4 bytes). */
#define CTE_IXDATA_FIXED_TYPE_INT64 0x03   /**< `int64_t` (8 bytes). */
#define CTE_IXDATA_FIXED_TYPE_UINT8 0x04   /**< `uint8_t` (1 byte). */
#define CTE_IXDATA_FIXED_TYPE_UINT16 0x05  /**< `uint16_t` (2 bytes). */
#define CTE_IXDATA_FIXED_TYPE_UINT32 0x06  /**< `uint32_t` (4 bytes). */
#define CTE_IXDATA_FIXED_TYPE_UINT64 0x07  /**< `uint64_t` (8 bytes). */
#define CTE_IXDATA_FIXED_TYPE_FLOAT32 0x08 /**< `float` (4 bytes, IEEE 754). */
#define CTE_IXDATA_FIXED_TYPE_FLOAT64 0x09 /**< `double` (8 bytes, IEEE 754). */
/** @} */

/**
 * @name IxData Constant Value Codes
 * @brief Value codes for the Constant sub-type (SS=11), stored in bits 5-2 (LIP-0001).
 * @{
 */
#define CTE_IXDATA_CONST_VAL_FALSE 0x00 /**< Represents the boolean value `false`. */
#define CTE_IXDATA_CONST_VAL_TRUE 0x01  /**< Represents the boolean value `true`. */
/** @} */

/**
 * @def CTE_LEGACY_INDEX_MAX_VALUE
 * @brief The maximum value for a 4-bit legacy index.
 */
#define CTE_LEGACY_INDEX_MAX_VALUE 15

/**
 * @name Command Data Format
 * @brief Defines the format for the Command Data field (Tag 11).
 * @{
 */
#define CTE_COMMAND_FORMAT_FLAG_MASK 0x20 /**< Mask for the format flag (bit 5). */
#define CTE_COMMAND_FORMAT_SHORT 0x00     /**< Indicates the short format (payload length 0-31). */
#define CTE_COMMAND_FORMAT_EXTENDED 0x20  /**< Indicates the extended format (payload length 32-1197). */
/** @} */

/**
 * @name Command Data Lengths
 * @brief Defines length constraints for Command Data payloads.
 * @{
 */
#define CTE_COMMAND_SHORT_MAX_LEN 31     /**< Maximum payload length for the short format. */
#define CTE_COMMAND_EXTENDED_MIN_LEN 32  /**< Minimum payload length for the extended format. */
#define CTE_COMMAND_EXTENDED_MAX_LEN 1197/**< Maximum practical payload length for the extended format. */
/** @} */

/**
 * @brief Gets the size in bytes of a public key for a given crypto type.
 * @param type_code The crypto type code (e.g., CTE_CRYPTO_TYPE_ED25519).
 * @return The size of the public key in bytes.
 * @note This function will abort via `lea_abort` if an invalid type code is provided.
 */
size_t get_public_key_size(uint8_t type_code);

/**
 * @brief Gets the size in bytes of a signature list item for a given crypto type.
 *
 * For Ed25519, this is the full signature size. For PQC schemes like SLH-DSA,
 * this is the size of the signature's hash.
 *
 * @param type_code The crypto type code (e.g., CTE_CRYPTO_TYPE_ED25519).
 * @return The size of the signature item in bytes.
 * @note This function will abort via `lea_abort` if an invalid type code is provided.
 */
size_t get_signature_item_size(uint8_t type_code);

#endif // CTE_H
