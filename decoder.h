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
    uint8_t *data;            /**< @param data Pointer to the buffer containing the CTE encoded data. */
    size_t size;              /**< @param size Total size in bytes of the data buffer. */
    size_t position;          /**< @param position Current read position within the data buffer. */
    size_t last_vector_count; /**< @param last_vector_count Item count of the last vector read. */
    size_t
        last_vector_data_len; /**< @param last_vector_data_len Payload length of the last generic vector data read. */
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
 * @brief Decodes a full CTE stream using a callback mechanism.
 *
 * This function iterates through the entire data buffer in the decoder,
 * decoding each field and invoking the host-provided `__cte_data_handler`
 * for each one. This is the recommended high-performance decoding method.
 *
 * @param decoder A pointer to the initialized and loaded decoder context.
 * @return 0 on success, a non-zero error code on failure.
 */
int cte_decoder_run(cte_decoder_t *decoder);

#endif // DECODER_H
