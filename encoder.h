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

/**
 * @brief Begins a generic Vector Data field.
 *
 * Writes the Vector Data header, automatically selecting the short or extended
 * format based on the length. Reserves space for the payload.
 *
 * @param handle A pointer to the encoder context.
 * @param length The exact length of the vector data payload (0-1197).
 * @return A writable pointer to the start of the reserved space for the payload.
 * @note The caller is responsible for `memcpy`ing the payload into the returned pointer.
 * @warning Aborts on invalid parameters or if the write would exceed buffer capacity.
 */
void *cte_encoder_begin_vector_data(cte_encoder_t *handle, size_t length);
//void cte_encoder_end_vector_data(cte_encoder_t *handle, size_t length);


#endif // ENCODER_H
