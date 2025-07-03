#include "encoder.h"
#include <stdlea.h>

LEA_EXPORT(test)
void test()
{
    LEA_LOG("This is a test log message from the encoder.");
}
/**
 * @brief Checks if adding `needed` bytes would exceed the encoder's capacity.
 * @param encoder A pointer to the encoder context.
 * @param needed The number of bytes required.
 * @note Aborts via `lea_abort` if capacity is insufficient.
 */
#define CHECK_CAPACITY(encoder, needed)                       \
    if ((encoder)->position + (needed) > (encoder)->capacity) \
    {                                                         \
        lea_abort("Write past end of buffer capacity");       \
    }

/**
 * @brief Encodes a `uint64_t` value into a buffer using ULEB128 encoding.
 * @param handle A pointer to the encoder context.
 * @param write_offset The offset in the buffer where writing should start.
 * @param value The `uint64_t` value to encode.
 * @return The number of bytes written for the ULEB128 value.
 * @note Internal helper function.
 */
static size_t _encode_uleb128(cte_encoder_t *handle, size_t write_offset, uint64_t value)
{
    uint8_t *buf = handle->buffer + write_offset;
    size_t i = 0;
    do
    {
        CHECK_CAPACITY(handle, write_offset + i + 1);
        uint8_t byte = value & 0x7f;
        value >>= 7;
        if (value != 0)
        {
            byte |= 0x80;
        }
        buf[i++] = byte;
    } while (value != 0);
    return i;
}

/**
 * @brief Encodes an `int64_t` value into a buffer using SLEB128 encoding.
 * @param handle A pointer to the encoder context.
 * @param write_offset The offset in the buffer where writing should start.
 * @param value The `int64_t` value to encode.
 * @return The number of bytes written for the SLEB128 value.
 * @note Internal helper function.
 */
static size_t _encode_sleb128(cte_encoder_t *handle, size_t write_offset, int64_t value)
{
    uint8_t *buf = handle->buffer + write_offset;
    size_t i = 0;
    bool more = true;
    while (more)
    {
        CHECK_CAPACITY(handle, write_offset + i + 1);
        uint8_t byte = value & 0x7f;
        int64_t sign_bit = (byte & 0x40);
        value >>= 7;

        if (((value == 0 && !sign_bit)) || ((value == -1 && sign_bit)))
        {
            more = false;
        }
        else
        {
            byte |= 0x80;
        }
        buf[i++] = byte;
    }
    return i;
}

/**
 * @brief Writes a complete IxData Fixed Data field to the buffer.
 * @param handle A pointer to the encoder context.
 * @param type_code The 4-bit type code for the fixed data type.
 * @param data_size The size of the data to write.
 * @param data A pointer to the data to be written.
 * @note Internal helper function. Aborts on error.
 */
static void write_fixed_data_internal(cte_encoder_t *handle, uint8_t type_code, size_t data_size, const void *data)
{
    if (!handle || !data)
    {
        lea_abort("Null argument to write_fixed_data helper");
    }
    if (type_code >= 0x0A)
    {
        lea_abort("Attempted to write reserved IxData Fixed type code");
    }

    size_t total_size = 1 + data_size;
    CHECK_CAPACITY(handle, total_size);

    uint8_t header = CTE_TAG_IXDATA_FIELD | ((type_code & 0x0F) << 2) | CTE_IXDATA_SUBTYPE_FIXED;
    handle->buffer[handle->position++] = header;

    memcpy(handle->buffer + handle->position, data, data_size);
    handle->position += data_size;
}

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
LEA_EXPORT(cte_encoder_init)
cte_encoder_t *cte_encoder_init(size_t capacity)
{
    LEA_LOG("Initializing CTE encoder with capacity");
    if (capacity < 1)
    {
        lea_abort("Capacity must be at least 1 for the version byte");
    }

    cte_encoder_t *handle = malloc(sizeof(cte_encoder_t));
    handle->buffer = malloc(capacity);
    handle->capacity = capacity;
    handle->position = 0;

    handle->buffer[handle->position++] = CTE_VERSION_BYTE;

    return handle;
}

/**
 * @brief Resets an existing encoder for reuse.
 *
 * Resets the encoder's write position to the beginning, allowing the buffer
 * to be overwritten with a new transaction. It rewrites the `CTE_VERSION_BYTE`.
 *
 * @param handle A pointer to the encoder context to reset.
 * @note This function will abort via `lea_abort` if the handle is NULL.
 */
LEA_EXPORT(cte_encoder_reset)
void cte_encoder_reset(cte_encoder_t *handle)
{
    if (!handle)
    {
        lea_abort("Null handle in reset");
    }
    handle->position = 0;

    CHECK_CAPACITY(handle, 1);
    handle->buffer[handle->position++] = CTE_VERSION_BYTE;
}

/**
 * @brief Gets a read-only pointer to the encoded data.
 *
 * @param handle A pointer to the encoder context.
 * @return A const pointer to the beginning of the encoded data buffer.
 * @note This function will abort via `lea_abort` if the handle is NULL.
 */
LEA_EXPORT(cte_encoder_get_data)
const uint8_t *cte_encoder_get_data(const cte_encoder_t *handle)
{
    if (!handle)
    {
        lea_abort("Null handle in get_data");
    }
    return handle->buffer;
}

/**
 * @brief Gets the current size of the encoded data.
 *
 * @param handle A pointer to the encoder context.
 * @return The number of bytes currently written to the buffer.
 * @note This function will abort via `lea_abort` if the handle is NULL.
 */
LEA_EXPORT(cte_encoder_get_size)
size_t cte_encoder_get_size(const cte_encoder_t *handle)
{
    if (!handle)
    {
        lea_abort("Null handle in get_size");
    }
    return handle->position;
}

/**
 * @brief Begins a Public Key Vector field.
 *
 * Writes the Public Key Vector header and reserves space for the key data.
 *
 * @param handle A pointer to the encoder context.
 * @param key_count The number of public keys in the vector (1-15).
 * @param size_code The entry size code for the keys.
 * @return A writable pointer to the start of the reserved space for key data.
 * @note The caller is responsible for `memcpy`ing the key data into the returned pointer.
 * @warning Aborts on invalid parameters or if the write would exceed buffer capacity.
 */

/**
 * @brief Writes an IxData Vector Index field.
 *
 * @param handle A pointer to the encoder context.
 * @param index The 4-bit index value to encode (0-15).
 * @warning Aborts on invalid parameters or if the write would exceed buffer capacity.
 */
LEA_EXPORT(cte_encoder_write_ixdata_vector_index)
void cte_encoder_write_ixdata_vector_index(cte_encoder_t *handle, uint8_t index)
{
    if (!handle)
    {
        lea_abort("Null handle in write_ixdata_vector_index");
    }
    if (index > CTE_VECTOR_INDEX_MAX_VALUE)
    {
        lea_abort("Vector index value out of range (0-15)");
    }

    CHECK_CAPACITY(handle, 1);
    uint8_t header = CTE_TAG_IXDATA_FIELD | ((index & 0x0F) << 2) | CTE_IXDATA_SUBTYPE_VECTOR_INDEX;
    handle->buffer[handle->position++] = header;
}

/**
 * @brief Writes an IxData field for a ULEB128 encoded unsigned integer.
 *
 * @param handle A pointer to the encoder context.
 * @param value The `uint64_t` value to encode.
 * @warning Aborts on invalid parameters or if the write would exceed buffer capacity.
 */
LEA_EXPORT(cte_encoder_write_ixdata_uleb128)
void cte_encoder_write_ixdata_uleb128(cte_encoder_t *handle, uint64_t value)
{
    if (!handle)
    {
        lea_abort("Null handle in write_ixdata_uleb128");
    }
    CHECK_CAPACITY(handle, 1);

    uint8_t header = CTE_TAG_IXDATA_FIELD | (CTE_IXDATA_VARINT_ENC_ULEB128 << 2) | CTE_IXDATA_SUBTYPE_VARINT;
    handle->buffer[handle->position] = header;

    size_t bytes_written = _encode_uleb128(handle, handle->position + 1, value);
    handle->position += (1 + bytes_written);
}

/**
 * @brief Writes an IxData field for a SLEB128 encoded signed integer.
 *
 * @param handle A pointer to the encoder context.
 * @param value The `int64_t` value to encode.
 * @warning Aborts on invalid parameters or if the write would exceed buffer capacity.
 */
LEA_EXPORT(cte_encoder_write_ixdata_sleb128)
void cte_encoder_write_ixdata_sleb128(cte_encoder_t *handle, int64_t value)
{
    if (!handle)
    {
        lea_abort("Null handle in write_ixdata_sleb128");
    }
    CHECK_CAPACITY(handle, 1);

    uint8_t header = CTE_TAG_IXDATA_FIELD | (CTE_IXDATA_VARINT_ENC_SLEB128 << 2) | CTE_IXDATA_SUBTYPE_VARINT;
    handle->buffer[handle->position] = header;

    size_t bytes_written = _encode_sleb128(handle, handle->position + 1, value);
    handle->position += (1 + bytes_written);
}

/**
 * @brief Writes an IxData field for a signed 8-bit integer.
 * @param handle A pointer to the encoder context.
 * @param value The `int8_t` value to encode.
 */
LEA_EXPORT(cte_encoder_write_ixdata_int8)
void cte_encoder_write_ixdata_int8(cte_encoder_t *handle, int8_t value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_INT8, sizeof(value), &value);
}

/**
 * @brief Writes an IxData field for a signed 16-bit integer.
 * @param handle A pointer to the encoder context.
 * @param value The `int16_t` value to encode.
 */
LEA_EXPORT(cte_encoder_write_ixdata_int16)
void cte_encoder_write_ixdata_int16(cte_encoder_t *handle, int16_t value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_INT16, sizeof(value), &value);
}

/**
 * @brief Writes an IxData field for a signed 32-bit integer.
 * @param handle A pointer to the encoder context.
 * @param value The `int32_t` value to encode.
 */
LEA_EXPORT(cte_encoder_write_ixdata_int32)
void cte_encoder_write_ixdata_int32(cte_encoder_t *handle, int32_t value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_INT32, sizeof(value), &value);
}

/**
 * @brief Writes an IxData field for a signed 64-bit integer.
 * @param handle A pointer to the encoder context.
 * @param value The `int64_t` value to encode.
 */
LEA_EXPORT(cte_encoder_write_ixdata_int64)
void cte_encoder_write_ixdata_int64(cte_encoder_t *handle, int64_t value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_INT64, sizeof(value), &value);
}

/**
 * @brief Writes an IxData field for an unsigned 8-bit integer.
 * @param handle A pointer to the encoder context.
 * @param value The `uint8_t` value to encode.
 */
LEA_EXPORT(cte_encoder_write_ixdata_uint8)
void cte_encoder_write_ixdata_uint8(cte_encoder_t *handle, uint8_t value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_UINT8, sizeof(value), &value);
}

/**
 * @brief Writes an IxData field for an unsigned 16-bit integer.
 * @param handle A pointer to the encoder context.
 * @param value The `uint16_t` value to encode.
 */
LEA_EXPORT(cte_encoder_write_ixdata_uint16)
void cte_encoder_write_ixdata_uint16(cte_encoder_t *handle, uint16_t value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_UINT16, sizeof(value), &value);
}

/**
 * @brief Writes an IxData field for an unsigned 32-bit integer.
 * @param handle A pointer to the encoder context.
 * @param value The `uint32_t` value to encode.
 */
LEA_EXPORT(cte_encoder_write_ixdata_uint32)
void cte_encoder_write_ixdata_uint32(cte_encoder_t *handle, uint32_t value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_UINT32, sizeof(value), &value);
}

/**
 * @brief Writes an IxData field for an unsigned 64-bit integer.
 * @param handle A pointer to the encoder context.
 * @param value The `uint64_t` value to encode.
 */
LEA_EXPORT(cte_encoder_write_ixdata_uint64)
void cte_encoder_write_ixdata_uint64(cte_encoder_t *handle, uint64_t value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_UINT64, sizeof(value), &value);
}

/**
 * @brief Writes an IxData field for a 32-bit float.
 * @param handle A pointer to the encoder context.
 * @param value The `float` value to encode.
 */
LEA_EXPORT(cte_encoder_write_ixdata_float32)
void cte_encoder_write_ixdata_float32(cte_encoder_t *handle, float value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_FLOAT32, sizeof(value), &value);
}

/**
 * @brief Writes an IxData field for a 64-bit double.
 * @param handle A pointer to the encoder context.
 * @param value The `double` value to encode.
 */
LEA_EXPORT(cte_encoder_write_ixdata_float64)
void cte_encoder_write_ixdata_float64(cte_encoder_t *handle, double value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_FLOAT64, sizeof(value), &value);
}

/**
 * @brief Writes an IxData field for a boolean constant.
 *
 * @param handle A pointer to the encoder context.
 * @param value The boolean value to encode (`true` or `false`).
 * @warning Aborts on invalid parameters or if the write would exceed buffer capacity.
 */
LEA_EXPORT(cte_encoder_write_ixdata_boolean)
void cte_encoder_write_ixdata_boolean(cte_encoder_t *handle, bool value)
{
    if (!handle)
    {
        lea_abort("Null handle in write_ixdata_constant");
    }
    CHECK_CAPACITY(handle, 1);

    uint8_t value_code = value ? CTE_IXDATA_CONST_VAL_TRUE : CTE_IXDATA_CONST_VAL_FALSE;
    if (value_code >= 0x02)
    {
        lea_abort("Attempted to write reserved IxData Constant value code");
    }

    uint8_t header = CTE_TAG_IXDATA_FIELD | ((value_code & 0x0F) << 2) | CTE_IXDATA_SUBTYPE_CONSTANT;
    handle->buffer[handle->position++] = header;
}

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
LEA_EXPORT(cte_encoder_begin_vector_data)
void *cte_encoder_begin_vector_data(cte_encoder_t *handle, size_t length)
{
    if (!handle)
    {
        lea_abort("Null handle in begin_vector_data");
    }

    size_t header_size;
    if (length <= CTE_VECTOR_SHORT_MAX_LEN)
    {
        header_size = 1;
        CHECK_CAPACITY(handle, header_size + length);
        uint8_t header = CTE_TAG_VECTOR_DATA | CTE_VECTOR_FORMAT_SHORT | (length & CTE_VECTOR_SHORT_MAX_LEN);
        handle->buffer[handle->position] = header;
    }
    else if (length >= CTE_VECTOR_EXTENDED_MIN_LEN && length <= CTE_VECTOR_EXTENDED_MAX_LEN)
    {
        header_size = 2;
        CHECK_CAPACITY(handle, header_size + length);
        uint8_t LH = (length >> 8) & 0x07;
        uint8_t header1 = CTE_TAG_VECTOR_DATA | CTE_VECTOR_FORMAT_EXTENDED | (LH << 2);
        uint8_t header2 = length & 0xFF;

        handle->buffer[handle->position] = header1;
        handle->buffer[handle->position + 1] = header2;
    }
    else
    {
        lea_abort("Vector data length out of range (0-1197)");
        return NULL;
    }

    void *write_ptr = handle->buffer + handle->position + header_size;
    handle->position += header_size + length;

    return write_ptr;
}

#ifdef ENV_WASM_MVP

// --- WASM-specific 'add' wrappers ---

LEA_EXPORT(cte_encoder_add_public_key_vector)
int cte_encoder_add_public_key_vector(cte_encoder_t *enc, uint8_t key_count, uint8_t size_code, const void *keys)
{
    if (!enc)
        lea_abort("Null handle in add_public_key_vector");
    if (key_count == 0 || key_count > CTE_VECTOR_MAX_LEN)
        lea_abort("Invalid key count");

    size_t item_size = get_public_key_size(size_code);
    size_t total_data_size = key_count * item_size;
    size_t total_field_size = 1 + total_data_size;

    if (enc->position + total_field_size > enc->capacity)
        lea_abort("Capacity error");

    uint8_t header = CTE_TAG_PUBLIC_KEY_VECTOR | ((key_count & 0x0F) << 2) | (size_code & CTE_VECTOR_ENTRY_SIZE_MASK);
    enc->buffer[enc->position] = header;

    memcpy(enc->buffer + enc->position + 1, keys, total_data_size);
    enc->position += total_field_size;
    return 0;
}

LEA_EXPORT(cte_encoder_add_signature_vector)
int cte_encoder_add_signature_vector(cte_encoder_t *enc, uint8_t sig_count, uint8_t size_code, const void *sigs)
{
    if (!enc)
        lea_abort("Null handle in add_signature_vector");
    if (sig_count == 0 || sig_count > CTE_VECTOR_MAX_LEN)
        lea_abort("Invalid sig count");

    size_t item_size = get_signature_item_size(size_code);
    size_t total_data_size = sig_count * item_size;
    size_t total_field_size = 1 + total_data_size;

    if (enc->position + total_field_size > enc->capacity)
        lea_abort("Capacity error");

    uint8_t header = CTE_TAG_SIGNATURE_VECTOR | ((sig_count & 0x0F) << 2) | (size_code & CTE_VECTOR_ENTRY_SIZE_MASK);
    enc->buffer[enc->position] = header;

    memcpy(enc->buffer + enc->position + 1, sigs, total_data_size);
    enc->position += total_field_size;
    return 0;
}

LEA_EXPORT(cte_encoder_add_vector_data)
int cte_encoder_add_vector_data(cte_encoder_t *enc, size_t length, const void *data)
{
    void *ptr = cte_encoder_begin_vector_data(enc, length);
    if (!ptr)
        return -1;
    memcpy(ptr, data, length);
    return 0;
}

#endif // ENV_WASM_MVP

