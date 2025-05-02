#ifndef DECODER_H
#define DECODER_H

#include "cte.h"
#include <stdlea.h>

/**
 * @brief Value returned by peek functions when the end of the buffer is reached.
 */
#define CTE_PEEK_EOF ((uint8_t)0xFF)

/**
 * @brief Structure to manage the CTE decoding process.
 * Holds the buffer containing the encoded data, its total size,
 * and the current read position.
 */
typedef struct
{
    uint8_t *data;   ///< Pointer to the buffer containing the CTE encoded data.
    size_t size;     ///< Total size in bytes of the data buffer.
    size_t position; ///< Current read position within the data buffer.
} cte_decoder_t;

/**
 * @brief Initializes and allocates memory for a new CTE decoder context and its internal buffer.
 * In a Wasm environment, this likely allocates from the module's linear memory
 * using a bump allocator strategy. The allocated buffer has a fixed size.
 * The caller must subsequently load the encoded data into the buffer using cte_decoder_load().
 * Aborts if size is 0 or exceeds CTE_MAX_TRANSACTION_SIZE.
 *
 * @param size The exact size in bytes of the CTE data that will be loaded into the decoder's buffer.
 * @return Pointer to the newly created decoder context. In Wasm, freeing this context
 * explicitly might not be required; memory is managed by the runtime or reset.
 */
cte_decoder_t *cte_decoder_init(size_t size);

/**
 * @brief Returns a writable pointer to the decoder's internal buffer.
 * This is intended for the caller to load the encoded CTE data into the buffer *after*
 * calling cte_decoder_init() and *before* starting any read/peek operations.
 *
 * @param decoder Pointer to the initialized decoder context.
 * @return A writable pointer to the internal data buffer where CTE data should be placed.
 */
uint8_t *cte_decoder_load(cte_decoder_t *decoder);

/**
 * @brief Resets the decoder's read position to the beginning (position 1, just after the version byte).
 * This allows the same loaded data buffer to be read again from the start.
 * It mimics freeing and reallocating in a bump allocator context by resetting the position pointer.
 * Does not modify buffer content or size. Aborts if the decoder handle is NULL.
 *
 * @param decoder Pointer to the decoder context to reset for reuse.
 */
void cte_decoder_reset(cte_decoder_t *decoder);

/**
 * @brief Peeks at the next byte in the buffer to determine the field tag (top 2 bits).
 * Does not advance the read position. Validates the version byte if at position 0.
 * Aborts if the decoder handle is NULL or the version byte is incorrect.
 *
 * @param decoder Pointer to the decoder context.
 * @return The tag value (CTE_TAG_PUBLIC_KEY_LIST, CTE_TAG_SIGNATURE_LIST, CTE_TAG_IXDATA_FIELD, CTE_TAG_COMMAND_DATA)
 * or -1 if the end of the buffer is reached.
 */
int cte_decoder_peek_tag(cte_decoder_t *decoder);

/**
 * @brief Peeks at the Public Key List header byte to read the key count (N).
 * Verifies that the next field has the correct tag (Tag 00). Does not advance position.
 * Aborts if the next field is not a Public Key List or if N is invalid (0 or > 15).
 *
 * @param decoder Pointer to the decoder context.
 * @return The number of keys (N, 1-15) declared in the header, or CTE_PEEK_EOF if end of buffer.
 */
uint8_t cte_decoder_peek_public_key_list_count(const cte_decoder_t *decoder);

/**
 * @brief Peeks at the Public Key List header byte to read the crypto type code (TT).
 * Verifies that the next field has the correct tag (Tag 00). Does not advance position.
 * Aborts if the next field is not a Public Key List.
 *
 * @param decoder Pointer to the decoder context.
 * @return The crypto type code (TT, 0-3) declared in the header, or CTE_PEEK_EOF if end of buffer.
 */
uint8_t cte_decoder_peek_public_key_list_type(const cte_decoder_t *decoder);

/**
 * @brief Reads and consumes a Public Key List field (header and data).
 * Verifies the header tag, count (N), and type code (TT). Checks buffer bounds.
 * Advances the read position past the entire field.
 * Aborts on errors (NULL handle, wrong tag, invalid N/TT, insufficient data).
 *
 * @param decoder Pointer to the decoder context.
 * @return A read-only pointer to the start of the contiguous key data within the decoder's buffer. The data length is N
 * * size(TT).
 */
const uint8_t *cte_decoder_read_public_key_list_data(cte_decoder_t *decoder);

/**
 * @brief Peeks at the Signature List header byte to read the item count (N).
 * Verifies that the next field has the correct tag (Tag 01). Does not advance position.
 * Aborts if the next field is not a Signature List or if N is invalid (0 or > 15).
 *
 * @param decoder Pointer to the decoder context.
 * @return The number of signatures/hashes (N, 1-15) declared in the header, or CTE_PEEK_EOF if end of buffer.
 */
uint8_t cte_decoder_peek_signature_list_count(const cte_decoder_t *decoder);

/**
 * @brief Peeks at the Signature List header byte to read the crypto type code (TT).
 * Verifies that the next field has the correct tag (Tag 01). Does not advance position.
 * Aborts if the next field is not a Signature List.
 *
 * @param decoder Pointer to the decoder context.
 * @return The crypto type code (TT, 0-3) declared in the header, or CTE_PEEK_EOF if end of buffer.
 */
uint8_t cte_decoder_peek_signature_list_type(const cte_decoder_t *decoder);

/**
 * @brief Reads and consumes a Signature List field (header and data).
 * Verifies the header tag, count (N), and type code (TT). Checks buffer bounds.
 * Advances the read position past the entire field.
 * Aborts on errors (NULL handle, wrong tag, invalid N/TT, insufficient data).
 *
 * @param decoder Pointer to the decoder context.
 * @return A read-only pointer to the start of the contiguous signature/hash data within the decoder's buffer. The data
 * length is N * size(TT).
 */
const uint8_t *cte_decoder_read_signature_list_data(cte_decoder_t *decoder);

/**
 * @brief Reads and consumes a 1-byte IxData field representing a Legacy Index Reference (Tag 10, SS=00).
 * Verifies the header tag and subtype. Extracts the 4-bit index.
 * Advances the read position by 1.
 * **Note:** Does not perform bounds checking against list sizes (as per LIP-0004). Application logic must validate the
 * index. Aborts on errors (NULL handle, wrong tag/subtype, insufficient data).
 *
 * @param decoder Pointer to the decoder context.
 * @return The decoded 4-bit index value (IIII, 0-15).
 */
uint8_t cte_decoder_read_ixdata_index_reference(cte_decoder_t *decoder);

/**
 * @brief Reads and consumes an IxData field containing a ULEB128 encoded unsigned integer (Tag 10, SS=01, EEEE=0001).
 * Verifies the header tag, subtype, and encoding scheme. Decodes the subsequent ULEB128 bytes.
 * Advances the read position past the header and the decoded ULEB128 bytes.
 * Aborts on errors (NULL handle, wrong tag/subtype/scheme, invalid ULEB128 data, overflow, insufficient data).
 *
 * @param decoder Pointer to the decoder context.
 * @return The decoded unsigned 64-bit integer value.
 */
uint64_t cte_decoder_read_ixdata_uleb128(cte_decoder_t *decoder);

/**
 * @brief Reads and consumes an IxData field containing an SLEB128 encoded signed integer (Tag 10, SS=01, EEEE=0010).
 * Verifies the header tag, subtype, and encoding scheme. Decodes the subsequent SLEB128 bytes.
 * Advances the read position past the header and the decoded SLEB128 bytes.
 * Aborts on errors (NULL handle, wrong tag/subtype/scheme, invalid SLEB128 data, overflow, insufficient data).
 *
 * @param decoder Pointer to the decoder context.
 * @return The decoded signed 64-bit integer value.
 */
int64_t cte_decoder_read_ixdata_sleb128(cte_decoder_t *decoder);

/**
 * @brief Reads and consumes an IxData field containing a fixed-size signed 8-bit integer (Tag 10, SS=10, TTTT=0000).
 * Verifies header, reads 1 data byte. Advances position by 2. Aborts on errors.
 * @param decoder Pointer to the decoder context.
 * @return The decoded int8_t value.
 */
int8_t cte_decoder_read_ixdata_int8(cte_decoder_t *decoder);

/**
 * @brief Reads and consumes an IxData field containing a fixed-size signed 16-bit integer (Tag 10, SS=10, TTTT=0001).
 * Verifies header, reads 2 data bytes (Little Endian). Advances position by 3. Aborts on errors.
 * @param decoder Pointer to the decoder context.
 * @return The decoded int16_t value.
 */
int16_t cte_decoder_read_ixdata_int16(cte_decoder_t *decoder);

/**
 * @brief Reads and consumes an IxData field containing a fixed-size signed 32-bit integer (Tag 10, SS=10, TTTT=0010).
 * Verifies header, reads 4 data bytes (Little Endian). Advances position by 5. Aborts on errors.
 * @param decoder Pointer to the decoder context.
 * @return The decoded int32_t value.
 */
int32_t cte_decoder_read_ixdata_int32(cte_decoder_t *decoder);

/**
 * @brief Reads and consumes an IxData field containing a fixed-size signed 64-bit integer (Tag 10, SS=10, TTTT=0011).
 * Verifies header, reads 8 data bytes (Little Endian). Advances position by 9. Aborts on errors.
 * @param decoder Pointer to the decoder context.
 * @return The decoded int64_t value.
 */
int64_t cte_decoder_read_ixdata_int64(cte_decoder_t *decoder);

/**
 * @brief Reads and consumes an IxData field containing a fixed-size unsigned 8-bit integer (Tag 10, SS=10, TTTT=0100).
 * Verifies header, reads 1 data byte. Advances position by 2. Aborts on errors.
 * @param decoder Pointer to the decoder context.
 * @return The decoded uint8_t value.
 */
uint8_t cte_decoder_read_ixdata_uint8(cte_decoder_t *decoder);

/**
 * @brief Reads and consumes an IxData field containing a fixed-size unsigned 16-bit integer (Tag 10, SS=10, TTTT=0101).
 * Verifies header, reads 2 data bytes (Little Endian). Advances position by 3. Aborts on errors.
 * @param decoder Pointer to the decoder context.
 * @return The decoded uint16_t value.
 */
uint16_t cte_decoder_read_ixdata_uint16(cte_decoder_t *decoder);

/**
 * @brief Reads and consumes an IxData field containing a fixed-size unsigned 32-bit integer (Tag 10, SS=10, TTTT=0110).
 * Verifies header, reads 4 data bytes (Little Endian). Advances position by 5. Aborts on errors.
 * @param decoder Pointer to the decoder context.
 * @return The decoded uint32_t value.
 */
uint32_t cte_decoder_read_ixdata_uint32(cte_decoder_t *decoder);

/**
 * @brief Reads and consumes an IxData field containing a fixed-size unsigned 64-bit integer (Tag 10, SS=10, TTTT=0111).
 * Verifies header, reads 8 data bytes (Little Endian). Advances position by 9. Aborts on errors.
 * @param decoder Pointer to the decoder context.
 * @return The decoded uint64_t value.
 */
uint64_t cte_decoder_read_ixdata_uint64(cte_decoder_t *decoder);

/**
 * @brief Reads and consumes an IxData field containing a fixed-size 32-bit float (Tag 10, SS=10, TTTT=1000).
 * Verifies header, reads 4 data bytes (IEEE 754, Little Endian). Advances position by 5. Aborts on errors.
 * @param decoder Pointer to the decoder context.
 * @return The decoded float value.
 */
float cte_decoder_read_ixdata_float32(cte_decoder_t *decoder);

/**
 * @brief Reads and consumes an IxData field containing a fixed-size 64-bit double (Tag 10, SS=10, TTTT=1001).
 * Verifies header, reads 8 data bytes (IEEE 754, Little Endian). Advances position by 9. Aborts on errors.
 * @param decoder Pointer to the decoder context.
 * @return The decoded double value.
 */
double cte_decoder_read_ixdata_float64(cte_decoder_t *decoder);

/**
 * @brief Reads and consumes a 1-byte IxData field representing a boolean constant (Tag 10, SS=11).
 * Verifies the header tag, subtype, and constant value code (must be 0 for false or 1 for true).
 * Advances the read position by 1.
 * Aborts on errors (NULL handle, wrong tag/subtype, invalid/reserved constant code, insufficient data).
 *
 * @param decoder Pointer to the decoder context.
 * @return The decoded boolean value (true if code is 1, false if code is 0).
 */
bool cte_decoder_read_ixdata_boolean(cte_decoder_t *decoder);

/**
 * @brief Peeks at the Command Data header to determine the payload length.
 * Verifies the field tag (Tag 11). Parses the length from the short (1 byte) or extended (2 byte) header format.
 * Does not advance the read position.
 * Aborts if the next field is not Command Data, or if the header format/padding/length is invalid.
 *
 * @param decoder Pointer to the decoder context.
 * @return The declared payload length in bytes (0-1197), or SIZE_MAX if end of buffer or format error during peek.
 */
size_t cte_decoder_peek_command_data_length(const cte_decoder_t *decoder);

/**
 * @brief Reads and consumes a Command Data field (header and payload).
 * Verifies the header tag and format. Parses the length. Checks buffer bounds.
 * Advances the read position past the entire field.
 * Aborts on errors (NULL handle, wrong tag, invalid format/length, insufficient data).
 *
 * @param decoder Pointer to the decoder context.
 * @return A read-only pointer to the start of the command data payload within the decoder's buffer. The data length was
 * returned by the peek function or can be calculated.
 */
const uint8_t *cte_decoder_read_command_data_payload(cte_decoder_t *decoder);

#endif // DECODER_H
