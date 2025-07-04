#ifndef ENCODER_H
#define ENCODER_H

#include "cte.h"
#include <stdlea.h>

/**
 * @file encoder.h
 * @brief Defines the functions and structures for the CTE Encoder.
 *
 * The encoder provides a stateful interface for building a CTE byte stream
 * by sequentially writing different field types.
 */

/**
 * @struct cte_encoder
 * @brief Manages the state of the CTE encoding process.
 *
 * This structure holds a pointer to the buffer where data is written,
 * its total allocated capacity, and the current write position, which
 * also represents the size of the encoded data so far.
 */
typedef struct cte_encoder
{
    uint8_t *buffer; /**< @param buffer Pointer to the allocated memory buffer for encoding. */
    size_t capacity; /**< @param capacity Total size in bytes of the allocated buffer. */
    size_t position; /**< @param position Current write position within the buffer. */
} cte_encoder_t;

/**
 * @brief Initializes a new CTE encoder context and its buffer.
 *
 * Allocates memory for the encoder structure and its internal buffer of the
 * specified capacity. It writes the `CTE_VERSION_BYTE` as the first byte.
 *
 * @param capacity The total size in bytes to allocate for the internal buffer.
 * @return A pointer to the newly created encoder context.
 * @note This function will abort via `lea_abort` if the capacity is less than 1.
 */
cte_encoder_t *cte_encoder_init(size_t capacity);

/**
 * @brief Resets an existing encoder for reuse.
 *
 * Resets the encoder's write position to the beginning, allowing the buffer
 * to be overwritten with a new transaction. It rewrites the `CTE_VERSION_BYTE`.
 *
 * @param handle A pointer to the encoder context to reset.
 * @note This function will abort via `lea_abort` if the handle is NULL.
 */
void cte_encoder_reset(cte_encoder_t *handle);

/**
 * @brief Gets a read-only pointer to the encoded data.
 *
 * @param handle A pointer to the encoder context.
 * @return A const pointer to the beginning of the encoded data buffer.
 * @note This function will abort via `lea_abort` if the handle is NULL.
 */
const uint8_t *cte_encoder_get_data(const cte_encoder_t *handle);

/**
 * @brief Gets the current size of the encoded data.
 *
 * @param handle A pointer to the encoder context.
 * @return The number of bytes currently written to the buffer.
 * @note This function will abort via `lea_abort` if the handle is NULL.
 */
size_t cte_encoder_get_size(const cte_encoder_t *handle);

/**
 * @brief Adds a complete Public Key Vector field to the encoder buffer.
 *
 * This function constructs and writes a Public Key Vector field, including its
 * header and the provided key data.
 *
 * @param enc A pointer to the encoder context.
 * @param key_count The number of public keys in the vector (1-15).
 * @param size_code The entry size code for the keys.
 * @param keys A pointer to the buffer containing the key data to be written.
 * @return Returns 0 on success.
 * @warning This function will abort via `lea_abort` on null pointers, invalid
 *          key counts, or if the write would exceed buffer capacity.
 */
int cte_encoder_add_public_key_vector(cte_encoder_t *enc, uint8_t key_count, uint8_t size_code, const void *keys);

/**
 * @brief Adds a complete Signature Vector field to the encoder buffer.
 *
 * This function constructs and writes a Signature Vector field, including its
 * header and the provided signature data.
 *
 * @param enc A pointer to the encoder context.
 * @param sig_count The number of signatures in the vector (1-15).
 * @param size_code The entry size code for the signatures.
 * @param sigs A pointer to the buffer containing the signature data to be written.
 * @return Returns 0 on success.
 * @warning This function will abort via `lea_abort` on null pointers, invalid
 *          signature counts, or if the write would exceed buffer capacity.
 */
int cte_encoder_add_signature_vector(cte_encoder_t *enc, uint8_t sig_count, uint8_t size_code, const void *sigs);

/**
 * @brief Adds a complete Vector Data field to the encoder buffer.
 *
 * This function uses `cte_encoder_begin_vector_data` to handle the header
 * and then copies the provided data into the buffer.
 *
 * @param enc A pointer to the encoder context.
 * @param length The length of the data to write.
 * @param data A pointer to the data buffer.
 * @return Returns 0 on success, -1 on failure (if `begin_vector_data` fails).
 */
int cte_encoder_add_vector_data(cte_encoder_t *enc, size_t length, const void *data);

/**
 * @brief Writes an IxData Vector Index field.
 *
 * @param handle A pointer to the encoder context.
 * @param index The 4-bit index value to encode (0-15).
 * @warning Aborts on invalid parameters or if the write would exceed buffer capacity.
 */
void cte_encoder_write_ixdata_vector_index(cte_encoder_t *handle, uint8_t index);

/**
 * @brief Writes an IxData field for a ULEB128 encoded unsigned integer.
 *
 * @param handle A pointer to the encoder context.
 * @param value The `uint64_t` value to encode.
 * @warning Aborts on invalid parameters or if the write would exceed buffer capacity.
 */
void cte_encoder_write_ixdata_uleb128(cte_encoder_t *handle, uint64_t value);

/**
 * @brief Writes an IxData field for a SLEB128 encoded signed integer.
 *
 * @param handle A pointer to the encoder context.
 * @param value The `int64_t` value to encode.
 * @warning Aborts on invalid parameters or if the write would exceed buffer capacity.
 */
void cte_encoder_write_ixdata_sleb128(cte_encoder_t *handle, int64_t value);

/**
 * @brief Writes an IxData field for a signed 8-bit integer.
 * @param handle A pointer to the encoder context.
 * @param value The `int8_t` value to encode.
 */
void cte_encoder_write_ixdata_int8(cte_encoder_t *handle, int8_t value);

/**
 * @brief Writes an IxData field for a signed 16-bit integer.
 * @param handle A pointer to the encoder context.
 * @param value The `int16_t` value to encode.
 */
void cte_encoder_write_ixdata_int16(cte_encoder_t *handle, int16_t value);

/**
 * @brief Writes an IxData field for a signed 32-bit integer.
 * @param handle A pointer to the encoder context.
 * @param value The `int32_t` value to encode.
 */
void cte_encoder_write_ixdata_int32(cte_encoder_t *handle, int32_t value);

/**
 * @brief Writes an IxData field for a signed 64-bit integer.
 * @param handle A pointer to the encoder context.
 * @param value The `int64_t` value to encode.
 */
void cte_encoder_write_ixdata_int64(cte_encoder_t *handle, int64_t value);

/**
 * @brief Writes an IxData field for an unsigned 8-bit integer.
 * @param handle A pointer to the encoder context.
 * @param value The `uint8_t` value to encode.
 */
void cte_encoder_write_ixdata_uint8(cte_encoder_t *handle, uint8_t value);

/**
 * @brief Writes an IxData field for an unsigned 16-bit integer.
 * @param handle A pointer to the encoder context.
 * @param value The `uint16_t` value to encode.
 */
void cte_encoder_write_ixdata_uint16(cte_encoder_t *handle, uint16_t value);

/**
 * @brief Writes an IxData field for an unsigned 32-bit integer.
 * @param handle A pointer to the encoder context.
 * @param value The `uint32_t` value to encode.
 */
void cte_encoder_write_ixdata_uint32(cte_encoder_t *handle, uint32_t value);

/**
 * @brief Writes an IxData field for an unsigned 64-bit integer.
 * @param handle A pointer to the encoder context.
 * @param value The `uint64_t` value to encode.
 */
void cte_encoder_write_ixdata_uint64(cte_encoder_t *handle, uint64_t value);

/**
 * @brief Writes an IxData field for a 32-bit float.
 * @param handle A pointer to the encoder context.
 * @param value The `float` value to encode.
 */
void cte_encoder_write_ixdata_float32(cte_encoder_t *handle, float value);

/**
 * @brief Writes an IxData field for a 64-bit double.
 * @param handle A pointer to the encoder context.
 * @param value The `double` value to encode.
 */
void cte_encoder_write_ixdata_float64(cte_encoder_t *handle, double value);

/**
 * @brief Writes an IxData field for a boolean constant.
 *
 * @param handle A pointer to the encoder context.
 * @param value The boolean value to encode (`true` or `false`).
 * @warning Aborts on invalid parameters or if the write would exceed buffer capacity.
 */
void cte_encoder_write_ixdata_boolean(cte_encoder_t *handle, bool value);


#endif // ENCODER_H
