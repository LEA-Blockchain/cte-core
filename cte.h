#ifndef CTE_H
#define CTE_H

#include <stdlea.h>

/**
 * @file cte.h
 * @brief Core definitions and constants for the Compact Transaction Encoding (CTE).
 *
 * This file defines the fundamental constants, tags, masks, and type codes
 * used throughout the CTE library, as specified by the active LIPs.
 */

/**
 * @def CTE_VERSION_BYTE
 * @brief The required first byte of any valid CTE transaction stream.
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
#define CTE_TAG_PUBLIC_KEY_VECTOR 0x00 /**< Tag for a Public Key Vector field (binary `00`). */
#define CTE_TAG_SIGNATURE_VECTOR 0x40  /**< Tag for a Signature Vector field (binary `01`). */
#define CTE_TAG_IXDATA_FIELD 0x80      /**< Tag for an IxData (Index/Extended Data) field (binary `10`). */
#define CTE_TAG_VECTOR_DATA 0xC0       /**< Tag for a generic Vector Data field (binary `11`). */
#define CTE_TAG_MASK 0xC0              /**< Mask to extract the 2-bit tag from a header byte. */
/** @} */

/**
 * @name Vector Entry Size Codes
 * @brief Generic entry size codes for Vectors (LIP-0005).
 * These codes are stored in the lower 2 bits of the vector's header byte.
 * @{
 */
#define CTE_VECTOR_ENTRY_SIZE_CODE_0 0x00 /**< Size code 0. */
#define CTE_VECTOR_ENTRY_SIZE_CODE_1 0x01 /**< Size code 1. */
#define CTE_VECTOR_ENTRY_SIZE_CODE_2 0x02 /**< Size code 2. */
#define CTE_VECTOR_ENTRY_SIZE_CODE_3 0x03 /**< Size code 3. */
#define CTE_VECTOR_ENTRY_SIZE_MASK 0x03   /**< Mask to extract the 2-bit size code from a header. */
/** @} */

/**
 * @name Vector Item Sizes
 * @brief Defines the byte sizes for vector entries based on the size code (LIP-0005).
 * @{
 */
#define CTE_PUBKEY_SIZE_CODE_0 32
#define CTE_PUBKEY_SIZE_CODE_1 64
#define CTE_PUBKEY_SIZE_CODE_2 128

#define CTE_SIGNATURE_SIZE_CODE_0 32
#define CTE_SIGNATURE_SIZE_CODE_1 64
#define CTE_SIGNATURE_SIZE_CODE_2 128
#define CTE_SIGNATURE_SIZE_CODE_3 29792
/** @} */

/**
 * @def CTE_VECTOR_MAX_LEN
 * @brief The maximum number of items allowed in a vector.
 * This is defined by the 4-bit length field (N) in the vector header.
 */
#define CTE_VECTOR_MAX_LEN 15

/**
 * @name IxData Field Sub-Types
 * @brief Sub-type codes for the IxData field (Tag 10), stored in the lower 2 bits (LIP-0001).
 * @{
 */
#define CTE_IXDATA_SUBTYPE_VECTOR_INDEX 0x00 /**< Sub-type for a 4-bit vector index. */
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
 * specific type of an upcoming field with a single function call.
 * @{
 */
// Tag 00: Public Key Vectors
#define CTE_PEEK_TYPE_PK_VECTOR_SIZE_0 0
#define CTE_PEEK_TYPE_PK_VECTOR_SIZE_1 1
#define CTE_PEEK_TYPE_PK_VECTOR_SIZE_2 2
#define CTE_PEEK_TYPE_PK_VECTOR_SIZE_3 3 // Unused but defined for completeness

// Tag 01: Signature Vectors
#define CTE_PEEK_TYPE_SIG_VECTOR_SIZE_0 4
#define CTE_PEEK_TYPE_SIG_VECTOR_SIZE_1 5
#define CTE_PEEK_TYPE_SIG_VECTOR_SIZE_2 6
#define CTE_PEEK_TYPE_SIG_VECTOR_SIZE_3 7

// Tag 10: IxData Fields
#define CTE_PEEK_TYPE_IXDATA_VECTOR_INDEX 8
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

// Tag 11: Vector Data
#define CTE_PEEK_TYPE_VECTOR_SHORT 24
#define CTE_PEEK_TYPE_VECTOR_EXTENDED 25
/** @} */

/**
 * @name IxData Varint Encoding Schemes
 * @brief Encoding scheme codes for the Varint sub-type (SS=01), stored in bits 5-2 (LIP-0001).
 * @{
 */
#define CTE_IXDATA_VARINT_ENC_ZERO 0x00
#define CTE_IXDATA_VARINT_ENC_ULEB128 0x01
#define CTE_IXDATA_VARINT_ENC_SLEB128 0x02
/** @} */

/**
 * @name IxData Fixed Data Type Codes
 * @brief Type codes for the Fixed Data sub-type (SS=10), stored in bits 5-2 (LIP-0001).
 * @{
 */
#define CTE_IXDATA_FIXED_TYPE_INT8 0x00
#define CTE_IXDATA_FIXED_TYPE_INT16 0x01
#define CTE_IXDATA_FIXED_TYPE_INT32 0x02
#define CTE_IXDATA_FIXED_TYPE_INT64 0x03
#define CTE_IXDATA_FIXED_TYPE_UINT8 0x04
#define CTE_IXDATA_FIXED_TYPE_UINT16 0x05
#define CTE_IXDATA_FIXED_TYPE_UINT32 0x06
#define CTE_IXDATA_FIXED_TYPE_UINT64 0x07
#define CTE_IXDATA_FIXED_TYPE_FLOAT32 0x08
#define CTE_IXDATA_FIXED_TYPE_FLOAT64 0x09
/** @} */

/**
 * @name IxData Constant Value Codes
 * @brief Value codes for the Constant sub-type (SS=11), stored in bits 5-2 (LIP-0001).
 * @{
 */
#define CTE_IXDATA_CONST_VAL_FALSE 0x00
#define CTE_IXDATA_CONST_VAL_TRUE 0x01
/** @} */

/**
 * @def CTE_VECTOR_INDEX_MAX_VALUE
 * @brief The maximum value for a 4-bit vector index.
 */
#define CTE_VECTOR_INDEX_MAX_VALUE 15

/**
 * @name Vector Data Format
 * @brief Defines the format for the generic Vector Data field (Tag 11).
 * @{
 */
#define CTE_VECTOR_FORMAT_FLAG_MASK 0x20
#define CTE_VECTOR_FORMAT_SHORT 0x00
#define CTE_VECTOR_FORMAT_EXTENDED 0x20
/** @} */

/**
 * @name Vector Data Lengths
 * @brief Defines length constraints for Vector Data payloads.
 * @{
 */
#define CTE_VECTOR_SHORT_MAX_LEN 31
#define CTE_VECTOR_EXTENDED_MIN_LEN 32
#define CTE_VECTOR_EXTENDED_MAX_LEN 1197
/** @} */

/**
 * @brief Gets the size in bytes of a public key for a given entry size code.
 * @param size_code The 2-bit size code from the vector header.
 * @return The size of the public key in bytes.
 * @note This function will abort via `lea_abort` if an invalid size code is provided.
 */
size_t get_public_key_size(uint8_t size_code);

/**
 * @brief Gets the size in bytes of a signature vector item for a given entry size code.
 * @param size_code The 2-bit size code from the vector header.
 * @return The size of the signature item in bytes.
 * @note This function will abort via `lea_abort` if an invalid size code is provided.
 */
size_t get_signature_item_size(uint8_t size_code);

#endif // CTE_H

