#ifndef DECODER_H
#define DECODER_H

#include "cte.h"
#include <stdlea.h>

/**
 * @file decoder.h
 * @brief Defines the functions and structures for the CTE Decoder.
 *
 * The decoder provides a stateful interface for parsing a CTE byte stream
 * by sequentially peeking at and reading different field types.
 */

/**
 * @def CTE_PEEK_EOF
 * @brief Value returned by peek functions when the end of the buffer is reached.
 */
#define CTE_PEEK_EOF ((uint8_t)0xFF)

// --- Tag 11: Vector Data ---
#define CTE_PEEK_SUBTYPE_VECTOR_SHORT 0x50    ///< Vector Data with a short payload (0-31 bytes).
#define CTE_PEEK_SUBTYPE_VECTOR_EXTENDED 0x51 ///< Vector Data with an extended payload (32-1197 bytes).
/** @} */

/**
 * @struct cte_decoder
 * @brief Manages the state of the CTE decoding process.
 *
 * This structure holds a pointer to the buffer containing the encoded data,
 * its total size, and the current read position.
 */
typedef struct
{
    uint8_t *data;   /**< @param data Pointer to the buffer containing the CTE encoded data. */
    size_t size;     /**< @param size Total size in bytes of the data buffer. */
    size_t position; /**< @param position Current read position within the data buffer. */
    size_t last_vector_count; /**< @param last_vector_count Item count of the last vector read. */
    size_t last_vector_data_len;    /**< @param last_vector_data_len Payload length of the last generic vector data read. */
} cte_decoder_t;

/**
 * @brief Initializes a new CTE decoder context and its buffer.
 *
 * Allocates memory for the decoder structure and its internal buffer of the
 * specified size. The caller must load the encoded data into the buffer
 * via `cte_decoder_load()` before parsing.
 *
 * @param size The exact size in bytes of the CTE data that will be loaded.
 * @return A pointer to the newly created decoder context.
 * @note This function will abort via `lea_abort` if size is 0 or exceeds `CTE_MAX_TRANSACTION_SIZE`.
 */
cte_decoder_t *cte_decoder_init(size_t size);

/**
 * @brief Returns a writable pointer to the decoder's internal buffer.
 *
 * This function should be used to load the encoded CTE data into the buffer
 * after initialization and before any read/peek operations.
 *
 * @param decoder A pointer to the initialized decoder context.
 * @return A writable pointer to the internal data buffer.
 */
uint8_t *cte_decoder_load(cte_decoder_t *decoder);

/**
 * @brief Resets the decoder's read position for buffer reuse.
 *
 * Resets the position to 1 (to skip the version byte), allowing the same
 * loaded data to be parsed again from the beginning.
 *
 * @param decoder A pointer to the decoder context to reset.
 * @note This function will abort via `lea_abort` if the decoder handle is NULL.
 */
void cte_decoder_reset(cte_decoder_t *decoder);

/**
 * @brief Peeks at the next field to get its unique type identifier.
 *
 * This is the primary function for inspecting the data stream without
 * advancing the read position. It returns a single, unambiguous identifier
 * (e.g., `CTE_PEEK_TYPE_PK_VECTOR_SIZE_0`, `CTE_PEEK_TYPE_IXDATA_ULEB128`)
 * that specifies the exact type of the upcoming field.
 *
 * If this is the first read operation, it also validates the CTE version
 * byte and advances the position past it.
 *
 * @param decoder A pointer to the decoder context.
 * @return The unique type identifier, or `CTE_PEEK_EOF` if the end of the
 *         buffer is reached.
 * @note This function will abort via `lea_abort` if the version byte is incorrect.
 */
int cte_decoder_peek_type(cte_decoder_t *decoder);

/**
 * @brief Reads and consumes an IxData Varint Zero field.
 *
 * This function simply consumes the header byte for a Varint field that
 * encodes the value 0.
 *
 * @param decoder A pointer to the decoder context.
 */
void cte_decoder_read_ixdata_varint_zero(cte_decoder_t *decoder);

/**
 * @brief Gets the number of items from the most recently read vector.
 * @param decoder A pointer to the decoder context.
 * @return The item count of the last vector read.
 */
size_t cte_decoder_get_last_vector_count(const cte_decoder_t *decoder);

/**
 * @brief Gets the payload length from the most recently read generic vector data.
 * @param decoder A pointer to the decoder context.
 * @return The payload length of the last vector data read.
 */
size_t cte_decoder_get_last_vector_data_payload_length(const cte_decoder_t *decoder);


/**
 * @brief Reads the data payload of a Public Key Vector.
 *
 * @param decoder A pointer to the decoder context.
 * @return A const pointer to the start of the key data within the decoder's buffer.
 * @warning Aborts if the next field is not a Public Key Vector.
 */
const uint8_t *cte_decoder_read_public_key_vector_data(cte_decoder_t *decoder);

/**
 * @brief Reads the data payload of a Signature Vector.
 *
 * @param decoder A pointer to the decoder context.
 * @return A const pointer to the start of the signature data within the decoder's buffer.
 * @warning Aborts if the next field is not a Signature Vector.
 */
const uint8_t *cte_decoder_read_signature_vector_data(cte_decoder_t *decoder);

/**
 * @brief Reads an IxData Vector Index field.
 *
 * @param decoder A pointer to the decoder context.
 * @return The decoded 4-bit index value (0-15).
 * @warning Aborts on errors (wrong tag/subtype, insufficient data).
 */
uint8_t cte_decoder_read_ixdata_vector_index(cte_decoder_t *decoder);

/**
 * @brief Reads an IxData ULEB128 encoded unsigned integer field.
 *
 * @param decoder A pointer to the decoder context.
 * @return The decoded `uint64_t` value.
 * @warning Aborts on errors (wrong tag/subtype, invalid encoding, insufficient data).
 */
uint64_t cte_decoder_read_ixdata_uleb128(cte_decoder_t *decoder);

/**
 * @brief Reads an IxData SLEB128 encoded signed integer field.
 *
 * @param decoder A pointer to the decoder context.
 * @return The decoded `int64_t` value.
 * @warning Aborts on errors (wrong tag/subtype, invalid encoding, insufficient data).
 */
int64_t cte_decoder_read_ixdata_sleb128(cte_decoder_t *decoder);

/**
 * @brief Reads an IxData signed 8-bit integer field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `int8_t` value.
 */
int8_t cte_decoder_read_ixdata_int8(cte_decoder_t *decoder);

/**
 * @brief Reads an IxData signed 16-bit integer field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `int16_t` value.
 */
int16_t cte_decoder_read_ixdata_int16(cte_decoder_t *decoder);

/**
 * @brief Reads an IxData signed 32-bit integer field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `int32_t` value.
 */
int32_t cte_decoder_read_ixdata_int32(cte_decoder_t *decoder);

/**
 * @brief Reads an IxData signed 64-bit integer field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `int64_t` value.
 */
int64_t cte_decoder_read_ixdata_int64(cte_decoder_t *decoder);

/**
 * @brief Reads an IxData unsigned 8-bit integer field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `uint8_t` value.
 */
uint8_t cte_decoder_read_ixdata_uint8(cte_decoder_t *decoder);

/**
 * @brief Reads an IxData unsigned 16-bit integer field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `uint16_t` value.
 */
uint16_t cte_decoder_read_ixdata_uint16(cte_decoder_t *decoder);

/**
 * @brief Reads an IxData unsigned 32-bit integer field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `uint32_t` value.
 */
uint32_t cte_decoder_read_ixdata_uint32(cte_decoder_t *decoder);

/**
 * @brief Reads an IxData unsigned 64-bit integer field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `uint64_t` value.
 */
uint64_t cte_decoder_read_ixdata_uint64(cte_decoder_t *decoder);

/**
 * @brief Reads an IxData 32-bit float field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `float` value.
 */
float cte_decoder_read_ixdata_float32(cte_decoder_t *decoder);

/**
 * @brief Reads an IxData 64-bit double field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `double` value.
 */
double cte_decoder_read_ixdata_float64(cte_decoder_t *decoder);

/**
 * @brief Reads an IxData boolean constant field.
 *
 * @param decoder A pointer to the decoder context.
 * @return The decoded boolean value (`true` or `false`).
 * @warning Aborts on errors (wrong tag/subtype, invalid constant code).
 */
bool cte_decoder_read_ixdata_boolean(cte_decoder_t *decoder);

/**
 * @brief Reads the payload of a generic Vector Data field.
 *
 * @param decoder A pointer to the decoder context.
 * @return A const pointer to the start of the payload data within the decoder's buffer.
 * @warning Aborts if the next field is not Vector Data or the header is invalid.
 */
const uint8_t *cte_decoder_read_vector_data_payload(cte_decoder_t *decoder);


#endif // DECODER_H
