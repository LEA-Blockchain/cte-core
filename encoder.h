#ifndef ENCODER_H
#define ENCODER_H

#include "cte.h"
#include <stdlea.h>

/**
 * @brief Structure to manage the CTE encoding process.
 * Holds the buffer where data is written, its total capacity,
 * and the current write position.
 */
typedef struct cte_encoder
{
    uint8_t *buffer; ///< Pointer to the allocated memory buffer for encoding.
    size_t capacity; ///< Total size in bytes of the allocated buffer.
    size_t position; ///< Current write position within the buffer (number of bytes written).
} cte_encoder_t;

/**
 * @brief Initializes and allocates memory for a new CTE encoder context and its buffer.
 * Writes the CTE version byte as the first byte.
 * In a Wasm environment, this likely allocates from the module's linear memory
 * using a bump allocator strategy. The allocated buffer has a fixed capacity.
 * Aborts if requested capacity is insufficient (e.g., < 1).
 *
 * @param capacity The total fixed size in bytes to allocate for the internal buffer.
 * @return Pointer to the newly created encoder context. In Wasm, freeing this context
 * explicitly might not be required; memory is managed by the runtime or reset.
 */
cte_encoder_t *cte_encoder_init(size_t capacity);

/**
 * @brief Resets the encoder's write position to the beginning (after the version byte).
 * This allows the previously allocated buffer to be reused for encoding a new transaction,
 * assuming the original capacity is still sufficient. It mimics freeing and reallocating
 * in a bump allocator context by resetting the position pointer.
 * Writes the CTE version byte at the start. Does not change buffer capacity.
 * Aborts if the handle is NULL.
 *
 * @param handle Pointer to the encoder context to reset for reuse.
 */
void cte_encoder_reset(cte_encoder_t *handle);

/**
 * @brief Gets a read-only pointer to the start of the buffer containing the encoded data.
 * Aborts if the handle is NULL.
 *
 * @param handle Pointer to the encoder context.
 * @return Const pointer to the beginning of the encoded data buffer.
 */
const uint8_t *cte_encoder_get_data(const cte_encoder_t *handle);

/**
 * @brief Gets the current size (number of bytes written) of the encoded data.
 * Aborts if the handle is NULL.
 *
 * @param handle Pointer to the encoder context.
 * @return The number of bytes currently encoded in the buffer (equal to the write position).
 */
size_t cte_encoder_get_size(const cte_encoder_t *handle);

/**
 * @brief Writes the Public Key List header (Tag 00) and reserves space for the keys.
 * Calculates required space based on key count and type code (determining key size).
 * Advances the encoder position past the header and the reserved space.
 * Aborts on invalid parameters (NULL handle, count out of range 1-15, invalid type code) or buffer overflow.
 *
 * @param handle Pointer to the encoder context.
 * @param key_count The number of public keys in the list (N), must be between 1 and 15.
 * @param type_code The cryptographic scheme identifier (TT, e.g., CTE_CRYPTO_TYPE_ED25519), determining the size of
 * each key.
 * @return A writable pointer to the start of the reserved space where the actual key data should be copied by the
 * caller.
 */
void *cte_encoder_begin_public_key_list(cte_encoder_t *handle, uint8_t key_count, uint8_t type_code);

/**
 * @brief Writes the Signature List header (Tag 01) and reserves space for the signatures or hashes.
 * Calculates required space based on item count and type code (determining item size - full signature or hash).
 * Advances the encoder position past the header and the reserved space.
 * Aborts on invalid parameters (NULL handle, count out of range 1-15, invalid type code) or buffer overflow.
 *
 * @param handle Pointer to the encoder context.
 * @param sig_count The number of signatures or signature hashes in the list (N), must be between 1 and 15.
 * @param type_code The cryptographic scheme identifier (TT, e.g., CTE_CRYPTO_TYPE_ED25519), determining the size of
 * each item (signature or hash).
 * @return A writable pointer to the start of the reserved space where the actual signature/hash data should be copied
 * by the caller.
 */
void *cte_encoder_begin_signature_list(cte_encoder_t *handle, uint8_t sig_count, uint8_t type_code);

/**
 * @brief Writes a 1-byte IxData field for a Legacy Index Reference (Tag 10, SS=00).
 * Encodes the provided index value into the header byte.
 * Advances the encoder position by 1.
 * Aborts on invalid parameters (NULL handle, index out of range 0-15) or buffer overflow.
 *
 * @param handle Pointer to the encoder context.
 * @param index The 4-bit index value (IIII) to encode, must be between 0 and 15.
 */
void cte_encoder_write_ixdata_index_reference(cte_encoder_t *handle, uint8_t index);

/**
 * @brief Writes an IxData field for an unsigned variable-length integer using ULEB128 (Tag 10, SS=01, EEEE=0001).
 * Writes the appropriate IxData header byte followed by the ULEB128 encoded value.
 * Advances the encoder position by 1 (header) + number of bytes used for ULEB128 encoding.
 * Aborts on invalid parameters (NULL handle) or buffer overflow during encoding.
 *
 * @param handle Pointer to the encoder context.
 * @param value The unsigned 64-bit integer value to encode.
 */
void cte_encoder_write_ixdata_uleb128(cte_encoder_t *handle, uint64_t value);

/**
 * @brief Writes an IxData field for a signed variable-length integer using SLEB128 (Tag 10, SS=01, EEEE=0010).
 * Writes the appropriate IxData header byte followed by the SLEB128 encoded value.
 * Advances the encoder position by 1 (header) + number of bytes used for SLEB128 encoding.
 * Aborts on invalid parameters (NULL handle) or buffer overflow during encoding.
 *
 * @param handle Pointer to the encoder context.
 * @param value The signed 64-bit integer value to encode.
 */
void cte_encoder_write_ixdata_sleb128(cte_encoder_t *handle, int64_t value);

/**
 * @brief Writes an IxData field for a fixed-size signed 8-bit integer (Tag 10, SS=10, TTTT=0000).
 * Writes the header byte and the 1-byte value. Advances position by 2. Aborts on errors/overflow.
 *
 * @param handle Pointer to the encoder context.
 * @param value The int8_t value to encode.
 */
void cte_encoder_write_ixdata_int8(cte_encoder_t *handle, int8_t value);

/**
 * @brief Writes an IxData field for a fixed-size signed 16-bit integer (Tag 10, SS=10, TTTT=0001).
 * Writes the header byte and the 2-byte value (Little Endian). Advances position by 3. Aborts on errors/overflow.
 *
 * @param handle Pointer to the encoder context.
 * @param value The int16_t value to encode.
 */
void cte_encoder_write_ixdata_int16(cte_encoder_t *handle, int16_t value);

/**
 * @brief Writes an IxData field for a fixed-size signed 32-bit integer (Tag 10, SS=10, TTTT=0010).
 * Writes the header byte and the 4-byte value (Little Endian). Advances position by 5. Aborts on errors/overflow.
 *
 * @param handle Pointer to the encoder context.
 * @param value The int32_t value to encode.
 */
void cte_encoder_write_ixdata_int32(cte_encoder_t *handle, int32_t value);

/**
 * @brief Writes an IxData field for a fixed-size signed 64-bit integer (Tag 10, SS=10, TTTT=0011).
 * Writes the header byte and the 8-byte value (Little Endian). Advances position by 9. Aborts on errors/overflow.
 *
 * @param handle Pointer to the encoder context.
 * @param value The int64_t value to encode.
 */
void cte_encoder_write_ixdata_int64(cte_encoder_t *handle, int64_t value);

/**
 * @brief Writes an IxData field for a fixed-size unsigned 8-bit integer (Tag 10, SS=10, TTTT=0100).
 * Writes the header byte and the 1-byte value. Advances position by 2. Aborts on errors/overflow.
 *
 * @param handle Pointer to the encoder context.
 * @param value The uint8_t value to encode.
 */
void cte_encoder_write_ixdata_uint8(cte_encoder_t *handle, uint8_t value);

/**
 * @brief Writes an IxData field for a fixed-size unsigned 16-bit integer (Tag 10, SS=10, TTTT=0101).
 * Writes the header byte and the 2-byte value (Little Endian). Advances position by 3. Aborts on errors/overflow.
 *
 * @param handle Pointer to the encoder context.
 * @param value The uint16_t value to encode.
 */
void cte_encoder_write_ixdata_uint16(cte_encoder_t *handle, uint16_t value);

/**
 * @brief Writes an IxData field for a fixed-size unsigned 32-bit integer (Tag 10, SS=10, TTTT=0110).
 * Writes the header byte and the 4-byte value (Little Endian). Advances position by 5. Aborts on errors/overflow.
 *
 * @param handle Pointer to the encoder context.
 * @param value The uint32_t value to encode.
 */
void cte_encoder_write_ixdata_uint32(cte_encoder_t *handle, uint32_t value);

/**
 * @brief Writes an IxData field for a fixed-size unsigned 64-bit integer (Tag 10, SS=10, TTTT=0111).
 * Writes the header byte and the 8-byte value (Little Endian). Advances position by 9. Aborts on errors/overflow.
 *
 * @param handle Pointer to the encoder context.
 * @param value The uint64_t value to encode.
 */
void cte_encoder_write_ixdata_uint64(cte_encoder_t *handle, uint64_t value);

/**
 * @brief Writes an IxData field for a fixed-size 32-bit float (Tag 10, SS=10, TTTT=1000).
 * Writes the header byte and the 4-byte value (IEEE 754, Little Endian). Advances position by 5. Aborts on
 * errors/overflow.
 *
 * @param handle Pointer to the encoder context.
 * @param value The float value to encode.
 */
void cte_encoder_write_ixdata_float32(cte_encoder_t *handle, float value);

/**
 * @brief Writes an IxData field for a fixed-size 64-bit double (Tag 10, SS=10, TTTT=1001).
 * Writes the header byte and the 8-byte value (IEEE 754, Little Endian). Advances position by 9. Aborts on
 * errors/overflow.
 *
 * @param handle Pointer to the encoder context.
 * @param value The double value to encode.
 */
void cte_encoder_write_ixdata_float64(cte_encoder_t *handle, double value);

/**
 * @brief Writes a 1-byte IxData field for a boolean constant (Tag 10, SS=11).
 * Writes the header byte `10 0000 11` for false or `10 0001 11` for true.
 * Advances the encoder position by 1.
 * Aborts on invalid parameters (NULL handle) or buffer overflow.
 *
 * @param handle Pointer to the encoder context.
 * @param value The boolean value to encode (true or false).
 */
void cte_encoder_write_ixdata_boolean(cte_encoder_t *handle, bool value);

/**
 * @brief Writes the Command Data header (Tag 11) and reserves space for the payload.
 * Automatically selects the short (1 byte header) or extended (2 byte header) format based on the payload length.
 * Advances the encoder position past the header and the reserved payload space.
 * Aborts on invalid parameters (NULL handle, length out of range 0-1197) or buffer overflow.
 *
 * @param handle Pointer to the encoder context.
 * @param length The exact length in bytes of the command data payload that will be written. Must be between 0 and 1197.
 * @return A writable pointer to the start of the reserved space where the actual payload data should be copied by the
 * caller.
 */
void *cte_encoder_begin_command_data(cte_encoder_t *handle, size_t length);

#endif // ENCODER_H
