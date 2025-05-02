#include "encoder.h"
#include <stdlea.h>

#define CHECK_CAPACITY(encoder, needed)                       \
    if ((encoder)->position + (needed) > (encoder)->capacity) \
    {                                                         \
        lea_abort("Write past end of buffer capacity");       \
    }

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
            more = false; // Use false
        }
        else
        {
            byte |= 0x80;
        }
        buf[i++] = byte;
    }
    return i;
}

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

LEA_EXPORT(cte_encoder_init)
cte_encoder_t *cte_encoder_init(size_t capacity)
{
    if (capacity < 1) // Minimum is version byte
    {
        lea_abort("Null buffer provided to init with non-zero capacity");
    }

    cte_encoder_t *handle = malloc(sizeof(cte_encoder_t));
    handle->buffer = malloc(capacity);
    handle->capacity = capacity;
    handle->position = 0;

    handle->buffer[handle->position++] = CTE_VERSION_BYTE;

    return handle;
}

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

LEA_EXPORT(cte_encoder_get_data)
const uint8_t *cte_encoder_get_data(const cte_encoder_t *handle)
{
    if (!handle)
    {
        lea_abort("Null handle in get_data");
    }
    return handle->buffer;
}

LEA_EXPORT(cte_encoder_get_size)
size_t cte_encoder_get_size(const cte_encoder_t *handle)
{
    if (!handle)
    {
        lea_abort("Null handle in get_size");
    }
    return handle->position;
}

LEA_EXPORT(cte_encoder_begin_public_key_list)
void *cte_encoder_begin_public_key_list(cte_encoder_t *handle, uint8_t key_count, uint8_t type_code)
{
    if (!handle)
    {
        lea_abort("Null handle in begin_public_key_list");
    }
    if (key_count == 0 || key_count > CTE_LIST_MAX_LEN)
    {
        lea_abort("Invalid public key list length (must be 1-15)");
    }
    size_t item_size = get_public_key_size(type_code); // Will abort if invalid

    size_t total_data_size = key_count * item_size;
    size_t total_field_size = 1 + total_data_size;

    CHECK_CAPACITY(handle, total_field_size);

    uint8_t header = CTE_TAG_PUBLIC_KEY_LIST | ((key_count & 0x0F) << 2) | (type_code & CTE_CRYPTO_TYPE_MASK);
    handle->buffer[handle->position] = header;

    void *write_ptr = handle->buffer + handle->position + 1;
    handle->position += total_field_size;

    return write_ptr;
}

LEA_EXPORT(cte_encoder_begin_signature_list)
void *cte_encoder_begin_signature_list(cte_encoder_t *handle, uint8_t sig_count, uint8_t type_code)
{
    if (!handle)
    {
        lea_abort("Null handle in begin_signature_list");
    }
    if (sig_count == 0 || sig_count > CTE_LIST_MAX_LEN)
    {
        lea_abort("Invalid signature list length (must be 1-15)");
    }
    size_t item_size = get_signature_item_size(type_code); // Will abort if invalid

    size_t total_data_size = sig_count * item_size;
    size_t total_field_size = 1 + total_data_size;

    CHECK_CAPACITY(handle, total_field_size);

    uint8_t header = CTE_TAG_SIGNATURE_LIST | ((sig_count & 0x0F) << 2) | (type_code & CTE_CRYPTO_TYPE_MASK);
    handle->buffer[handle->position] = header;

    void *write_ptr = handle->buffer + handle->position + 1;
    handle->position += total_field_size;

    return write_ptr;
}

LEA_EXPORT(cte_encoder_write_ixdata_index_reference)
void cte_encoder_write_ixdata_index_reference(cte_encoder_t *handle, uint8_t index)
{
    if (!handle)
    {
        lea_abort("Null handle in write_ixdata_legacy_index");
    }
    if (index > CTE_LEGACY_INDEX_MAX_VALUE)
    {
        lea_abort("Legacy index value out of range (0-15)");
    }

    CHECK_CAPACITY(handle, 1);
    uint8_t header = CTE_TAG_IXDATA_FIELD | ((index & 0x0F) << 2) | CTE_IXDATA_SUBTYPE_LEGACY_INDEX;
    handle->buffer[handle->position++] = header;
}

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

// Specific Fixed Type Writers
LEA_EXPORT(cte_encoder_write_ixdata_int8)
void cte_encoder_write_ixdata_int8(cte_encoder_t *handle, int8_t value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_INT8, sizeof(value), &value);
}
LEA_EXPORT(cte_encoder_write_ixdata_int16)
void cte_encoder_write_ixdata_int16(cte_encoder_t *handle, int16_t value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_INT16, sizeof(value), &value);
}
LEA_EXPORT(cte_encoder_write_ixdata_int32)
void cte_encoder_write_ixdata_int32(cte_encoder_t *handle, int32_t value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_INT32, sizeof(value), &value);
}
LEA_EXPORT(cte_encoder_write_ixdata_int64)
void cte_encoder_write_ixdata_int64(cte_encoder_t *handle, int64_t value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_INT64, sizeof(value), &value);
}
LEA_EXPORT(cte_encoder_write_ixdata_uint8)
void cte_encoder_write_ixdata_uint8(cte_encoder_t *handle, uint8_t value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_UINT8, sizeof(value), &value);
}
LEA_EXPORT(cte_encoder_write_ixdata_uint16)
void cte_encoder_write_ixdata_uint16(cte_encoder_t *handle, uint16_t value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_UINT16, sizeof(value), &value);
}
LEA_EXPORT(cte_encoder_write_ixdata_uint32)
void cte_encoder_write_ixdata_uint32(cte_encoder_t *handle, uint32_t value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_UINT32, sizeof(value), &value);
}
LEA_EXPORT(cte_encoder_write_ixdata_uint64)
void cte_encoder_write_ixdata_uint64(cte_encoder_t *handle, uint64_t value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_UINT64, sizeof(value), &value);
}
LEA_EXPORT(cte_encoder_write_ixdata_float32)
void cte_encoder_write_ixdata_float32(cte_encoder_t *handle, float value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_FLOAT32, sizeof(value), &value);
}
LEA_EXPORT(cte_encoder_write_ixdata_float64)
void cte_encoder_write_ixdata_float64(cte_encoder_t *handle, double value)
{
    write_fixed_data_internal(handle, CTE_IXDATA_FIXED_TYPE_FLOAT64, sizeof(value), &value);
}
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
LEA_EXPORT(cte_encoder_begin_command_data)
void *cte_encoder_begin_command_data(cte_encoder_t *handle, size_t length)
{
    if (!handle)
    {
        lea_abort("Null handle in begin_command_data");
    }

    size_t header_size;
    if (length <= CTE_COMMAND_SHORT_MAX_LEN)
    {
        header_size = 1;
        CHECK_CAPACITY(handle, header_size + length);
        uint8_t header = CTE_TAG_COMMAND_DATA | CTE_COMMAND_FORMAT_SHORT | (length & CTE_COMMAND_SHORT_MAX_LEN);
        handle->buffer[handle->position] = header;
    }
    else if (length >= CTE_COMMAND_EXTENDED_MIN_LEN && length <= CTE_COMMAND_EXTENDED_MAX_LEN)
    {
        header_size = 2;
        CHECK_CAPACITY(handle, header_size + length);
        uint8_t LH = (length >> 8) & 0x07;
        uint8_t header1 = CTE_TAG_COMMAND_DATA | CTE_COMMAND_FORMAT_EXTENDED | (LH << 2);
        uint8_t header2 = length & 0xFF;

        handle->buffer[handle->position] = header1;
        handle->buffer[handle->position + 1] = header2;
    }
    else
    {
        lea_abort("Command data length out of range (0-1197)");
        return NULL; // Unreachable
    }

    void *write_ptr = handle->buffer + handle->position + header_size;
    handle->position += header_size + length;

    return write_ptr;
}

