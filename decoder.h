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
 * @brief Peeks at the next byte to determine the field tag.
 *
 * Does not advance the read position. If this is the first read operation,
 * it validates the version byte and advances the position past it.
 *
 * @param decoder A pointer to the decoder context.
 * @return The 2-bit tag value (e.g., `CTE_TAG_PUBLIC_KEY_LIST`), or -1 on EOF.
 * @note This function will abort if the version byte is incorrect.
 */
int cte_decoder_peek_tag(cte_decoder_t *decoder);

/**
 * @brief Peeks at the next byte to determine the field's subtype.
 *
 * The meaning of the returned subtype depends on the field's tag.
 * - For Lists: Returns the 2-bit crypto type.
 * - For IxData: Returns the 2-bit IxData subtype.
 * - For Command Data: Returns the format (0 for Short, 1 for Extended).
 *
 * @param decoder A pointer to the decoder context.
 * @return The subtype code, or `CTE_PEEK_EOF` (-1) if at the end of the buffer.
 */
int cte_decoder_peek_subtype(const cte_decoder_t *decoder);

/**
 * @brief Peeks at a Public Key List header to read the key count.
 *
 * @param decoder A pointer to the decoder context.
 * @return The number of keys (1-15) in the list, or `CTE_PEEK_EOF` on EOF.
 * @warning Aborts if the next field is not a Public Key List or N is invalid.
 */
uint8_t cte_decoder_peek_public_key_list_count(const cte_decoder_t *decoder);

/**
 * @brief Peeks at a Public Key List header to read the crypto type.
 *
 * @param decoder A pointer to the decoder context.
 * @return The crypto type code (0-3), or `CTE_PEEK_EOF` on EOF.
 * @warning Aborts if the next field is not a Public Key List.
 */
uint8_t cte_decoder_peek_public_key_list_type(const cte_decoder_t *decoder);

/**
 * @brief Reads and consumes a Public Key List field.
 *
 * @param decoder A pointer to the decoder context.
 * @return A read-only pointer to the start of the key data within the decoder's buffer.
 * @warning Aborts on errors (wrong tag, invalid N/TT, insufficient data).
 */
const uint8_t *cte_decoder_read_public_key_list_data(cte_decoder_t *decoder);

/**
 * @brief Peeks at a Signature List header to read the item count.
 *
 * @param decoder A pointer to the decoder context.
 * @return The number of signatures/hashes (1-15), or `CTE_PEEK_EOF` on EOF.
 * @warning Aborts if the next field is not a Signature List or N is invalid.
 */
uint8_t cte_decoder_peek_signature_list_count(const cte_decoder_t *decoder);

/**
 * @brief Peeks at a Signature List header to read the crypto type.
 *
 * @param decoder A pointer to the decoder context.
 * @return The crypto type code (0-3), or `CTE_PEEK_EOF` on EOF.
 * @warning Aborts if the next field is not a Signature List.
 */
uint8_t cte_decoder_peek_signature_list_type(const cte_decoder_t *decoder);

/**
 * @brief Reads and consumes a Signature List field.
 *
 * @param decoder A pointer to the decoder context.
 * @return A read-only pointer to the start of the signature data within the decoder's buffer.
 * @warning Aborts on errors (wrong tag, invalid N/TT, insufficient data).
 */
const uint8_t *cte_decoder_read_signature_list_data(cte_decoder_t *decoder);

/**
 * @brief Reads an IxData Legacy Index Reference field.
 *
 * @param decoder A pointer to the decoder context.
 * @return The decoded 4-bit index value (0-15).
 * @warning Aborts on errors (wrong tag/subtype, insufficient data).
 */
uint8_t cte_decoder_read_ixdata_index_reference(cte_decoder_t *decoder);

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
 * @brief Peeks at a Command Data header to determine the payload length.
 *
 * @param decoder A pointer to the decoder context.
 * @return The declared payload length in bytes (0-1197), or `SIZE_MAX` on error.
 * @warning Aborts if the next field is not Command Data or the header is invalid.
 */
size_t cte_decoder_peek_command_data_length(const cte_decoder_t *decoder);

/**
 * @brief Reads and consumes a Command Data field.
 *
 * @param decoder A pointer to the decoder context.
 * @return A read-only pointer to the start of the payload data within the decoder's buffer.
 * @warning Aborts on errors (wrong tag, invalid format, insufficient data).
 */
const uint8_t *cte_decoder_read_command_data_payload(cte_decoder_t *decoder);

#endif // DECODER_H
