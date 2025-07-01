#include "decoder.h"
#include <stdlea.h>

/**
 * @brief Checks if reading `needed` bytes would exceed the buffer's bounds.
 * @param decoder A pointer to the decoder context.
 * @param needed The number of bytes required.
 * @note Aborts via `lea_abort` if bounds are exceeded.
 */
#define CHECK_BOUNDS(decoder, needed)                     \
    if ((decoder)->position + (needed) > (decoder)->size) \
    {                                                     \
        lea_abort("Read past end of buffer");             \
    }

/**
 * @brief Checks if reading `needed` bytes is possible without aborting.
 * @param decoder A pointer to the decoder context.
 * @param needed The number of bytes required.
 * @return `true` if the read is safe, `false` otherwise.
 */
#define CHECK_BOUNDS_PEEK(decoder, needed) (((decoder)->position + (needed)) <= (decoder)->size)

/**
 * @brief Checks if a header's tag matches the expected tag.
 * @param header The header byte to check.
 * @param expected_tag The expected 2-bit tag.
 * @note Aborts via `lea_abort` on mismatch.
 */
#define CHECK_TAG(header, expected_tag)              \
    if (((header) & CTE_TAG_MASK) != (expected_tag)) \
    {                                                \
        lea_abort("Unexpected field tag");           \
    }

/**
 * @brief Checks if a header's tag matches the expected tag without aborting.
 * @param header The header byte to check.
 * @param expected_tag The expected 2-bit tag.
 * @return `true` if the tags match, `false` otherwise.
 */
#define CHECK_TAG_PEEK(header, expected_tag) (((header) & CTE_TAG_MASK) == (expected_tag))

/**
 * @brief Checks if padding bits within a value are zero.
 * @param value The value containing padding bits.
 * @param mask The bitmask to isolate the padding bits.
 * @param context A string describing the context for the error message.
 * @note Aborts via `lea_abort` if any padding bits are non-zero.
 */
#define CHECK_PADDING_ZERO(value, mask, context)        \
    if (((value) & (mask)) != 0)                        \
    {\n        lea_abort("Non-zero padding bits in " context); \
    }

/**
 * @brief Checks if padding bits are zero without aborting.
 * @param value The value containing padding bits.
 * @param mask The bitmask to isolate the padding bits.
 * @return `true` if padding is valid (zero), `false` otherwise.
 */
#define CHECK_PADDING_ZERO_PEEK(value, mask) (((value) & (mask)) == 0)

/**
 * @brief Peeks at the next byte in the buffer without advancing the position.
 * @param decoder A pointer to the decoder context.
 * @return The header byte as an integer, or -1 if the end of the buffer is reached.
 * @note Internal helper function. Aborts if the decoder handle is NULL.
 */
static int _cte_decoder_peek_header_byte(const cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in peek_header_byte");
    }
    if (!CHECK_BOUNDS_PEEK(decoder, 1))
    {
        return -1; // end of buffer
    }
    return (int)decoder->data[decoder->position];
}

/**
 * @brief Consumes and validates an IxData header byte.
 * @param decoder A pointer to the decoder context.
 * @param expected_subtype The expected IxData subtype.
 * @return The validated header byte.
 * @note Internal helper function. Aborts on tag/subtype mismatch or if out of bounds.
 */
static uint8_t _consume_ixdata_header(cte_decoder_t *decoder, uint8_t expected_subtype)
{
    CHECK_BOUNDS(decoder, 1);
    uint8_t header = decoder->data[decoder->position];

    CHECK_TAG(header, CTE_TAG_IXDATA_FIELD);

    uint8_t SS = header & CTE_IXDATA_SUBTYPE_MASK;
    if (SS != expected_subtype)
    {
        lea_abort("Unexpected IxData subtype");
    }

    decoder->position++;
    return header;
}

/**
 * @brief Decodes a ULEB128 value from the decoder's current position.
 * @param decoder A pointer to the decoder context.
 * @param out_value A pointer to a `uint64_t` to store the decoded value.
 * @note Internal helper function. Aborts on invalid encoding or overflow.
 */
static void _decode_uleb128(cte_decoder_t *decoder, uint64_t *out_value)
{
    uint64_t result = 0;
    int shift = 0;
    uint8_t byte;
    const size_t max_bytes = 10;

    for (size_t i = 0; i < max_bytes; ++i)
    {
        CHECK_BOUNDS(decoder, 1);
        byte = decoder->data[decoder->position++];

        if (shift >= 64 || (shift == 63 && (byte & 0xFE) != 0))
        {
            lea_abort("ULEB128 overflow detected (value > 64 bits)");
        }
        result |= ((uint64_t)(byte & 0x7F)) << shift;

        if (!(byte & 0x80))
        {
            *out_value = result;
            return;
        }
        shift += 7;
    }
    lea_abort("Invalid ULEB128 encoding (unterminated sequence > 10 bytes)");
}

/**
 * @brief Decodes an SLEB128 value from the decoder's current position.
 * @param decoder A pointer to the decoder context.
 * @param out_value A pointer to an `int64_t` to store the decoded value.
 * @note Internal helper function. Aborts on invalid encoding or overflow.
 */
static void _decode_sleb128(cte_decoder_t *decoder, int64_t *out_value)
{
    int64_t result = 0;
    int shift = 0;
    uint8_t byte;
    const size_t max_bytes = 10;

    for (size_t i = 0; i < max_bytes; ++i)
    {
        CHECK_BOUNDS(decoder, 1);
        byte = decoder->data[decoder->position++];
        result |= ((int64_t)(byte & 0x7F)) << shift;
        shift += 7;

        if (!(byte & 0x80))
        {
            if ((shift < 64) && (byte & 0x40))
            {
                result |= -((int64_t)1 << shift);
            }
            *out_value = result;
            return;
        }
        if (shift >= 64)
        {
            lea_abort("Invalid SLEB128 encoding (too many bytes/overflow)");
        }
    }
    lea_abort("Invalid SLEB128 encoding (unterminated sequence > 10 bytes)");
}

/**
 * @brief Reads a fixed-size data type from an IxData field.
 * @param decoder A pointer to the decoder context.
 * @param expected_type_code The expected 4-bit type code for the fixed data.
 * @param expected_size The expected size of the data.
 * @param out_buffer A pointer to the buffer to store the decoded data.
 * @note Internal helper function. Aborts on error.
 */
static void _read_fixed_data(cte_decoder_t *decoder, uint8_t expected_type_code, size_t expected_size, void *out_buffer)
{
    if (!decoder || !out_buffer)
    {
        lea_abort("Null argument to _read_fixed_data helper");
    }
    uint8_t header = _consume_ixdata_header(decoder, CTE_IXDATA_SUBTYPE_FIXED);
    uint8_t TTTT = (header >> 2) & 0x0F;

    if (TTTT != expected_type_code)
    {
        lea_abort("Unexpected IxData Fixed type code");
    }
    if (TTTT >= 0x0A)
    {
        lea_abort("Reserved IxData Fixed type code encountered");
    }

    CHECK_BOUNDS(decoder, expected_size);
    memcpy(out_buffer, decoder->data + decoder->position, expected_size);
    decoder->position += expected_size;
}

/**
 * @brief Parses a Command Data header to determine its length and size.
 * @param decoder A pointer to the decoder context.
 * @param out_header_size A pointer to store the size of the header (1 or 2 bytes).
 * @return The length of the payload, or `SIZE_MAX` on error.
 * @note Internal helper function. Aborts on invalid header format.
 */
static size_t _parse_command_data_header(const cte_decoder_t *decoder, size_t *out_header_size)
{
    size_t current_pos = decoder->position;

    if (!CHECK_BOUNDS_PEEK(decoder, 1))
    {
        *out_header_size = 0;
        return SIZE_MAX;
    }
    uint8_t header1 = decoder->data[current_pos];

    if (!CHECK_TAG_PEEK(header1, CTE_TAG_COMMAND_DATA))
    {
        lea_abort("Expected Command Data tag in peek/parse");
        return SIZE_MAX;
    }

    size_t length = 0;
    if ((header1 & CTE_COMMAND_FORMAT_FLAG_MASK) == CTE_COMMAND_FORMAT_SHORT)
    {
        *out_header_size = 1;
        length = header1 & CTE_COMMAND_SHORT_MAX_LEN;
    }
    else
    {
        if (!CHECK_PADDING_ZERO_PEEK(header1, 0x03))
        {
            lea_abort("Non-zero padding bits in Command Data Extended Header Byte 1");
        }
        if (!CHECK_BOUNDS_PEEK(decoder, 2))
        {
            *out_header_size = 0;
            return SIZE_MAX;
        }
        *out_header_size = 2;
        uint8_t header2 = decoder->data[current_pos + 1];

        size_t LH = (header1 >> 2) & 0x07;
        size_t LL = header2;
        length = (LH << 8) | LL;

        if (length < CTE_COMMAND_EXTENDED_MIN_LEN || length > CTE_COMMAND_EXTENDED_MAX_LEN)
        {
            lea_abort("Invalid extended command data length");
        }
    }
    return length;
}

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
LEA_EXPORT(cte_decoder_init)
cte_decoder_t *cte_decoder_init(size_t size)
{
    if (size == 0)
    {
        lea_abort("Zero size buffer");
    }
    if (size > CTE_MAX_TRANSACTION_SIZE)
    {
        lea_abort("Initial buffer size exceeds max transaction size");
    }

    cte_decoder_t *decoder = malloc(sizeof(cte_decoder_t));
    decoder->data = malloc(size);
    decoder->size = size;
    decoder->position = 0;
    decoder->last_list_count = 0;
    decoder->last_cmd_len = 0;

    return decoder;
}

/**
 * @brief Returns a writable pointer to the decoder's internal buffer.
 *
 * This function should be used to load the encoded CTE data into the buffer
 * after initialization and before any read/peek operations.
 *
 * @param decoder A pointer to the initialized decoder context.
 * @return A writable pointer to the internal data buffer.
 */
LEA_EXPORT(cte_decoder_load)
uint8_t *cte_decoder_load(cte_decoder_t *decoder)
{
    return decoder->data;
}

/**
 * @brief Resets the decoder's read position for buffer reuse.
 *
 * Resets the position to 1 (to skip the version byte), allowing the same
 * loaded data to be parsed again from the beginning.
 *
 * @param decoder A pointer to the decoder context to reset.
 * @note This function will abort via `lea_abort` if the decoder handle is NULL.
 */
LEA_EXPORT(cte_decoder_reset)
void cte_decoder_reset(cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in reset");
    }
    decoder->position = 1;
}

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
LEA_EXPORT(cte_decoder_peek_type)
int cte_decoder_peek_type(cte_decoder_t *decoder)
{
    if (decoder->position == 0)
    {
        if (decoder->data[0] != CTE_VERSION_BYTE)
        {
            lea_abort("Invalid version byte");
        }
        else
        {
            decoder->position++;
        }
    }

    int header_byte = _cte_decoder_peek_header_byte(decoder);
    if (header_byte == -1)
    {
        return CTE_PEEK_EOF;
    }

    int tag = header_byte & CTE_TAG_MASK;

    switch (tag)
    {
    case CTE_TAG_PUBLIC_KEY_LIST:
    {
        uint8_t crypto_type = header_byte & CTE_CRYPTO_TYPE_MASK;
        switch (crypto_type)
        {
        case CTE_CRYPTO_TYPE_ED25519:
            return CTE_PEEK_TYPE_PK_LIST_ED25519;
        case CTE_CRYPTO_TYPE_SLH_DSA_128F:
            return CTE_PEEK_TYPE_PK_LIST_SLH_128F;
        case CTE_CRYPTO_TYPE_SLH_DSA_192F:
            return CTE_PEEK_TYPE_PK_LIST_SLH_192F;
        case CTE_CRYPTO_TYPE_SLH_DSA_256F:
            return CTE_PEEK_TYPE_PK_LIST_SLH_256F;
        }
        break;
    }
    case CTE_TAG_SIGNATURE_LIST:
    {
        uint8_t crypto_type = header_byte & CTE_CRYPTO_TYPE_MASK;
        switch (crypto_type)
        {
        case CTE_CRYPTO_TYPE_ED25519:
            return CTE_PEEK_TYPE_SIG_LIST_ED25519;
        case CTE_CRYPTO_TYPE_SLH_DSA_128F:
            return CTE_PEEK_TYPE_SIG_LIST_SLH_128F;
        case CTE_CRYPTO_TYPE_SLH_DSA_192F:
            return CTE_PEEK_TYPE_SIG_LIST_SLH_192F;
        case CTE_CRYPTO_TYPE_SLH_DSA_256F:
            return CTE_PEEK_TYPE_SIG_LIST_SLH_256F;
        }
        break;
    }
    case CTE_TAG_IXDATA_FIELD:
    {
        uint8_t ss = header_byte & CTE_IXDATA_SUBTYPE_MASK;
        uint8_t detail_code = (header_byte >> 2) & 0x0F;
        switch (ss)
        {
        case CTE_IXDATA_SUBTYPE_LEGACY_INDEX:
            return CTE_PEEK_TYPE_IXDATA_LEGACY_INDEX;
        case CTE_IXDATA_SUBTYPE_VARINT:
            switch (detail_code)
            {
            case CTE_IXDATA_VARINT_ENC_ZERO:
                return CTE_PEEK_TYPE_IXDATA_VARINT_ZERO;
            case CTE_IXDATA_VARINT_ENC_ULEB128:
                return CTE_PEEK_TYPE_IXDATA_ULEB128;
            case CTE_IXDATA_VARINT_ENC_SLEB128:
                return CTE_PEEK_TYPE_IXDATA_SLEB128;
            }
            break;
        case CTE_IXDATA_SUBTYPE_FIXED:
            switch (detail_code)
            {
            case CTE_IXDATA_FIXED_TYPE_INT8:
                return CTE_PEEK_TYPE_IXDATA_INT8;
            case CTE_IXDATA_FIXED_TYPE_INT16:
                return CTE_PEEK_TYPE_IXDATA_INT16;
            case CTE_IXDATA_FIXED_TYPE_INT32:
                return CTE_PEEK_TYPE_IXDATA_INT32;
            case CTE_IXDATA_FIXED_TYPE_INT64:
                return CTE_PEEK_TYPE_IXDATA_INT64;
            case CTE_IXDATA_FIXED_TYPE_UINT8:
                return CTE_PEEK_TYPE_IXDATA_UINT8;
            case CTE_IXDATA_FIXED_TYPE_UINT16:
                return CTE_PEEK_TYPE_IXDATA_UINT16;
            case CTE_IXDATA_FIXED_TYPE_UINT32:
                return CTE_PEEK_TYPE_IXDATA_UINT32;
            case CTE_IXDATA_FIXED_TYPE_UINT64:
                return CTE_PEEK_TYPE_IXDATA_UINT64;
            case CTE_IXDATA_FIXED_TYPE_FLOAT32:
                return CTE_PEEK_TYPE_IXDATA_FLOAT32;
            case CTE_IXDATA_FIXED_TYPE_FLOAT64:
                return CTE_PEEK_TYPE_IXDATA_FLOAT64;
            }
            break;
        case CTE_IXDATA_SUBTYPE_CONSTANT:
            switch (detail_code)
            {
            case CTE_IXDATA_CONST_VAL_FALSE:
                return CTE_PEEK_TYPE_IXDATA_CONST_FALSE;
            case CTE_IXDATA_CONST_VAL_TRUE:
                return CTE_PEEK_TYPE_IXDATA_CONST_TRUE;
            }
            break;
        }
        break;
    }
    case CTE_TAG_COMMAND_DATA:
        return (header_byte & CTE_COMMAND_FORMAT_FLAG_MASK)
                   ? CTE_PEEK_TYPE_CMD_EXTENDED
                   : CTE_PEEK_TYPE_CMD_SHORT;
    }

    return -1; // Should not happen with valid CTE
}



/**
 * @brief Reads and consumes a Public Key List field.
 *
 * @param decoder A pointer to the decoder context.
 * @return A read-only pointer to the start of the key data within the decoder's buffer.
 * @warning Aborts on errors (wrong tag, invalid N/TT, insufficient data).
 */
LEA_EXPORT(cte_decoder_read_public_key_list_data)
const uint8_t *cte_decoder_read_public_key_list_data(cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in read_public_key_list_data");
    }
    CHECK_BOUNDS(decoder, 1);
    uint8_t header = decoder->data[decoder->position];

    CHECK_TAG(header, CTE_TAG_PUBLIC_KEY_LIST);

    uint8_t N = (header >> 2) & 0x0F;
    uint8_t TT = header & CTE_CRYPTO_TYPE_MASK;

    if (N == 0 || N > CTE_LIST_MAX_LEN)
    {
        lea_abort("Invalid public key list length read (N must be 1-15)");
    }

    size_t item_size = get_public_key_size(TT);
    size_t total_data_size = N * item_size;

    CHECK_BOUNDS(decoder, 1 + total_data_size);

    decoder->position++;
    decoder->last_list_count = N;

    const uint8_t *data_ptr = decoder->data + decoder->position;
    decoder->position += total_data_size;

    return data_ptr;
}



/**
 * @brief Reads and consumes a Signature List field.
 *
 * @param decoder A pointer to the decoder context.
 * @return A read-only pointer to the start of the signature data within the decoder's buffer.
 * @warning Aborts on errors (wrong tag, invalid N/TT, insufficient data).
 */
LEA_EXPORT(cte_decoder_read_signature_list_data)
const uint8_t *cte_decoder_read_signature_list_data(cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in read_signature_list_data");
    }
    CHECK_BOUNDS(decoder, 1);
    uint8_t header = decoder->data[decoder->position];

    CHECK_TAG(header, CTE_TAG_SIGNATURE_LIST);

    uint8_t N = (header >> 2) & 0x0F;
    uint8_t TT = header & CTE_CRYPTO_TYPE_MASK;

    if (N == 0 || N > CTE_LIST_MAX_LEN)
    {
        lea_abort("Invalid signature list length read (N must be 1-15)");
    }

    size_t item_size = get_signature_item_size(TT);
    size_t total_data_size = N * item_size;

    CHECK_BOUNDS(decoder, 1 + total_data_size);

    decoder->position++;
    decoder->last_list_count = N;

    const uint8_t *data_ptr = decoder->data + decoder->position;
    decoder->position += total_data_size;

    return data_ptr;
}

/**
 * @brief Reads an IxData Legacy Index Reference field.
 *
 * @param decoder A pointer to the decoder context.
 * @return The decoded 4-bit index value (0-15).
 * @warning Aborts on errors (wrong tag/subtype, insufficient data).
 */
LEA_EXPORT(cte_decoder_read_ixdata_index_reference)
uint8_t cte_decoder_read_ixdata_index_reference(cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in read_ixdata_legacy_index");
    }
    uint8_t header = _consume_ixdata_header(decoder, CTE_IXDATA_SUBTYPE_LEGACY_INDEX);

    uint8_t index = (header >> 2) & 0x0F;

    return index;
}

/**
 * @brief Reads an IxData ULEB128 encoded unsigned integer field.
 *
 * @param decoder A pointer to the decoder context.
 * @return The decoded `uint64_t` value.
 * @warning Aborts on errors (wrong tag/subtype, invalid encoding, insufficient data).
 */
LEA_EXPORT(cte_decoder_read_ixdata_uleb128)
uint64_t cte_decoder_read_ixdata_uleb128(cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in read_ixdata_uleb128");
    }
    uint8_t header = _consume_ixdata_header(decoder, CTE_IXDATA_SUBTYPE_VARINT);
    uint8_t EEEE = (header >> 2) & 0x0F;

    if (EEEE != CTE_IXDATA_VARINT_ENC_ULEB128)
    {
        lea_abort("Expected Varint encoding scheme 1 (ULEB128)");
    }
    if (EEEE >= 0x03)
    {
        lea_abort("Reserved IxData Varint encoding scheme encountered");
    }

    uint64_t value;
    _decode_uleb128(decoder, &value);
    return value;
}

/**
 * @brief Reads an IxData SLEB128 encoded signed integer field.
 *
 * @param decoder A pointer to the decoder context.
 * @return The decoded `int64_t` value.
 * @warning Aborts on errors (wrong tag/subtype, invalid encoding, insufficient data).
 */
LEA_EXPORT(cte_decoder_read_ixdata_sleb128)
int64_t cte_decoder_read_ixdata_sleb128(cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in read_ixdata_sleb128");
    }
    uint8_t header = _consume_ixdata_header(decoder, CTE_IXDATA_SUBTYPE_VARINT);
    uint8_t EEEE = (header >> 2) & 0x0F;

    if (EEEE != CTE_IXDATA_VARINT_ENC_SLEB128)
    {
        lea_abort("Expected Varint encoding scheme 2 (SLEB128)");
    }
    if (EEEE >= 0x03)
    {
        lea_abort("Reserved IxData Varint encoding scheme encountered");
    }

    int64_t value;
    _decode_sleb128(decoder, &value);
    return value;
}

/**
 * @brief Reads an IxData signed 8-bit integer field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `int8_t` value.
 */
LEA_EXPORT(cte_decoder_read_ixdata_int8)
int8_t cte_decoder_read_ixdata_int8(cte_decoder_t *decoder)
{
    int8_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_INT8, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads an IxData signed 16-bit integer field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `int16_t` value.
 */
LEA_EXPORT(cte_decoder_read_ixdata_int16)
int16_t cte_decoder_read_ixdata_int16(cte_decoder_t *decoder)
{
    int16_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_INT16, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads an IxData signed 32-bit integer field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `int32_t` value.
 */
LEA_EXPORT(cte_decoder_read_ixdata_int32)
int32_t cte_decoder_read_ixdata_int32(cte_decoder_t *decoder)
{
    int32_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_INT32, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads an IxData signed 64-bit integer field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `int64_t` value.
 */
LEA_EXPORT(cte_decoder_read_ixdata_int64)
int64_t cte_decoder_read_ixdata_int64(cte_decoder_t *decoder)
{
    int64_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_INT64, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads an IxData unsigned 8-bit integer field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `uint8_t` value.
 */
LEA_EXPORT(cte_decoder_read_ixdata_uint8)
uint8_t cte_decoder_read_ixdata_uint8(cte_decoder_t *decoder)
{
    uint8_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_UINT8, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads an IxData unsigned 16-bit integer field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `uint16_t` value.
 */
LEA_EXPORT(cte_decoder_read_ixdata_uint16)
uint16_t cte_decoder_read_ixdata_uint16(cte_decoder_t *decoder)
{
    uint16_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_UINT16, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads an IxData unsigned 32-bit integer field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `uint32_t` value.
 */
LEA_EXPORT(cte_decoder_read_ixdata_uint32)
uint32_t cte_decoder_read_ixdata_uint32(cte_decoder_t *decoder)
{
    uint32_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_UINT32, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads an IxData unsigned 64-bit integer field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `uint64_t` value.
 */
LEA_EXPORT(cte_decoder_read_ixdata_uint64)
uint64_t cte_decoder_read_ixdata_uint64(cte_decoder_t *decoder)
{
    uint64_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_UINT64, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads an IxData 32-bit float field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `float` value.
 */
LEA_EXPORT(cte_decoder_read_ixdata_float32)
float cte_decoder_read_ixdata_float32(cte_decoder_t *decoder)
{
    float value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_FLOAT32, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads an IxData 64-bit double field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `double` value.
 */
LEA_EXPORT(cte_decoder_read_ixdata_float64)
double cte_decoder_read_ixdata_float64(cte_decoder_t *decoder)
{
    double value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_FLOAT64, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads an IxData boolean constant field.
 *
 * @param decoder A pointer to the decoder context.
 * @return The decoded boolean value (`true` or `false`).
 * @warning Aborts on errors (wrong tag/subtype, invalid constant code).
 */
LEA_EXPORT(cte_decoder_read_ixdata_boolean)
bool cte_decoder_read_ixdata_boolean(cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in read_ixdata_constant");
    }
    uint8_t header = _consume_ixdata_header(decoder, CTE_IXDATA_SUBTYPE_CONSTANT);
    uint8_t XXXX = (header >> 2) & 0x0F;

    if (XXXX == CTE_IXDATA_CONST_VAL_FALSE)
    {
        return false;
    }
    else if (XXXX == CTE_IXDATA_CONST_VAL_TRUE)
    {
        return true;
    }
    else
    {
        lea_abort("Reserved IxData Constant value code encountered");
        return false;
    }
}



/**
 * @brief Reads and consumes a Command Data field.
 *
 * @param decoder A pointer to the decoder context.
 * @return A read-only pointer to the start of the payload data within the decoder's buffer.
 * @warning Aborts on errors (wrong tag, invalid format, insufficient data).
 */
LEA_EXPORT(cte_decoder_read_command_data_payload)
const uint8_t *cte_decoder_read_command_data_payload(cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in read_command_data_payload");
    }

    size_t header_size;
    size_t length = _parse_command_data_header(decoder, &header_size);
    if (length == SIZE_MAX || header_size == 0)
    {
        lea_abort("Failed to parse command data header before read (EOF or internal error)");
    }

    CHECK_BOUNDS(decoder, header_size + length);

    decoder->position += header_size;
    decoder->last_cmd_len = length;

    const uint8_t *payload_ptr = decoder->data + decoder->position;

    decoder->position += length;

    return payload_ptr;
}

LEA_EXPORT(cte_decoder_read_ixdata_varint_zero)
void cte_decoder_read_ixdata_varint_zero(cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in read_ixdata_varint_zero");
    }
    uint8_t header = _consume_ixdata_header(decoder, CTE_IXDATA_SUBTYPE_VARINT);
    uint8_t EEEE = (header >> 2) & 0x0F;

    if (EEEE != CTE_IXDATA_VARINT_ENC_ZERO)
    {
        lea_abort("Expected Varint encoding scheme 0 (ZERO)");
    }
}

LEA_EXPORT(cte_decoder_get_last_list_count)
size_t cte_decoder_get_last_list_count(const cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in get_last_list_count");
    }
    return decoder->last_list_count;
}

LEA_EXPORT(cte_decoder_get_last_command_payload_length)
size_t cte_decoder_get_last_command_payload_length(const cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in get_last_command_payload_length");
    }
    return decoder->last_cmd_len;
}
