#include "decoder.h"
#include <stdlea.h>

/**
 * @brief Host-provided callback to handle decoded data fields.
 *
 * This function is implemented by the host (e.g., JavaScript) and is called
 * by `cte_decoder_run` for each field it decodes.
 *
 * @param type The unique type identifier of the decoded field (see `CTE_PEEK_TYPE_*`).
 * @param data A pointer to the buffer containing the field's data. For scalar
 *             types, this points to a temporary variable holding the value.
 * @param size The size of the data in bytes.
 */
LEA_IMPORT(env, __cte_data_handler)
void __cte_data_handler(int type, const void *data, size_t size);

/**
 * @brief Checks if reading `needed` bytes would exceed the buffer's bounds.
 * @param decoder A pointer to the decoder context.
 * @param needed The number of bytes required.
 * @note Aborts via `lea_abort` if bounds are exceeded.
 */
#define CHECK_BOUNDS(decoder, needed)                         \
    do                                                        \
    {                                                         \
        if ((decoder)->position + (needed) > (decoder)->size) \
        {                                                     \
            lea_abort("Read past end of buffer");             \
        }                                                     \
    } while (0)

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
#define CHECK_TAG(header, expected_tag)                  \
    do                                                   \
    {                                                    \
        if (((header) & CTE_TAG_MASK) != (expected_tag)) \
        {                                                \
            lea_abort("Unexpected field tag");           \
        }                                                \
    } while (0)

/**
 * @brief Checks if a header's tag matches the expected tag without aborting.
 * @param header The header byte to check.
 * @param expected_tag The expected 2-bit tag.
 * @return `true` if the tags match, `false` otherwise.
 */
#define CHECK_TAG_PEEK(header, expected_tag) (((header) & CTE_TAG_MASK) == (expected_tag))

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
 * @brief Parses a Vector Data header to determine its length and size.
 * @param decoder A pointer to the decoder context.
 * @param out_header_size A pointer to store the size of the header (1 or 2 bytes).
 * @return The length of the payload, or `SIZE_MAX` on error.
 * @note Internal helper function. Aborts on invalid header format.
 */
static size_t _parse_vector_data_header(const cte_decoder_t *decoder, size_t *out_header_size)
{
    size_t current_pos = decoder->position;

    if (!CHECK_BOUNDS_PEEK(decoder, 1))
    {
        *out_header_size = 0;
        return SIZE_MAX;
    }
    uint8_t header1 = decoder->data[current_pos];

    if (!CHECK_TAG_PEEK(header1, CTE_TAG_VECTOR_DATA))
    {
        lea_abort("Expected Vector Data tag in peek/parse");
        return SIZE_MAX;
    }

    size_t length = 0;
    if ((header1 & CTE_VECTOR_FORMAT_FLAG_MASK) == CTE_VECTOR_FORMAT_SHORT)
    {
        *out_header_size = 1;
        length = header1 & CTE_VECTOR_SHORT_MAX_LEN;
    }
    else
    {
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

        if (length < CTE_VECTOR_EXTENDED_MIN_LEN || length > CTE_VECTOR_EXTENDED_MAX_LEN)
        {
            lea_abort("Invalid extended vector data length");
        }
    }
    return length;
}

LEA_EXPORT(cte_decoder_init)
cte_decoder_t *cte_decoder_init(size_t size)
{
    if (size == 0)
    {
        lea_abort("Zero size buffer");
    }
    cte_decoder_t *decoder = malloc(sizeof(cte_decoder_t));
    decoder->data = malloc(size);
    decoder->size = size;
    decoder->position = 0;
    decoder->last_vector_count = 0;
    decoder->last_vector_data_len = 0;

    return decoder;
}

LEA_EXPORT(cte_decoder_load)
uint8_t *cte_decoder_load(cte_decoder_t *decoder)
{
    return decoder->data;
}

LEA_EXPORT(cte_decoder_reset)
void cte_decoder_reset(cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in reset");
    }
    decoder->position = 1;
}

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
    case CTE_TAG_PUBLIC_KEY_VECTOR:
    {
        uint8_t size_code = header_byte & CTE_VECTOR_ENTRY_SIZE_MASK;
        return CTE_PEEK_TYPE_PK_VECTOR_SIZE_0 + size_code;
    }
    case CTE_TAG_SIGNATURE_VECTOR:
    {
        uint8_t size_code = header_byte & CTE_VECTOR_ENTRY_SIZE_MASK;
        return CTE_PEEK_TYPE_SIG_VECTOR_SIZE_0 + size_code;
    }
    case CTE_TAG_IXDATA_FIELD:
    {
        uint8_t ss = header_byte & CTE_IXDATA_SUBTYPE_MASK;
        uint8_t detail_code = (header_byte >> 2) & 0x0F;
        switch (ss)
        {
        case CTE_IXDATA_SUBTYPE_VECTOR_INDEX:
            return CTE_PEEK_TYPE_IXDATA_VECTOR_INDEX;
        case CTE_IXDATA_SUBTYPE_VARINT:
            switch (detail_code)
            {
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
    case CTE_TAG_VECTOR_DATA:
        return (header_byte & CTE_VECTOR_FORMAT_FLAG_MASK) ? CTE_PEEK_TYPE_VECTOR_EXTENDED : CTE_PEEK_TYPE_VECTOR_SHORT;
    }

    return -1; // Should not happen with valid CTE
}

/**
 * @brief Reads the data payload of a Public Key Vector.
 *
 * Consumes the header, validates it, calculates the total data size,
 * and returns a pointer to the start of the key data. The decoder's
 * position is advanced past the entire field.
 *
 * @param decoder A pointer to the decoder context.
 * @return A const pointer to the start of the vector's data payload.
 * @note Internal helper function. Aborts on error.
 */
static const uint8_t *_cte_decoder_read_public_key_vector_data(cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in read_public_key_vector_data");
    }
    CHECK_BOUNDS(decoder, 1);
    uint8_t header = decoder->data[decoder->position];

    CHECK_TAG(header, CTE_TAG_PUBLIC_KEY_VECTOR);

    uint8_t N = (header >> 2) & 0x0F;
    uint8_t TT = header & CTE_VECTOR_ENTRY_SIZE_MASK;

    if (N == 0 || N > CTE_VECTOR_MAX_LEN)
    {
        lea_abort("Invalid public key vector length read (N must be 1-15)");
    }

    size_t item_size = get_public_key_size(TT);
    size_t total_data_size = N * item_size;

    CHECK_BOUNDS(decoder, 1 + total_data_size);

    decoder->position++;
    decoder->last_vector_count = N;

    const uint8_t *data_ptr = decoder->data + decoder->position;
    decoder->position += total_data_size;

    return data_ptr;
}


/**
 * @brief Reads the data payload of a Signature Vector.
 *
 * Consumes the header, validates it, calculates the total data size,
 * and returns a pointer to the start of the signature data. The decoder's
 * position is advanced past the entire field.
 *
 * @param decoder A pointer to the decoder context.
 * @return A const pointer to the start of the vector's data payload.
 * @note Internal helper function. Aborts on error.
 */
static const uint8_t *_cte_decoder_read_signature_vector_data(cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in read_signature_vector_data");
    }
    CHECK_BOUNDS(decoder, 1);
    uint8_t header = decoder->data[decoder->position];

    CHECK_TAG(header, CTE_TAG_SIGNATURE_VECTOR);

    uint8_t N = (header >> 2) & 0x0F;
    uint8_t TT = header & CTE_VECTOR_ENTRY_SIZE_MASK;

    if (N == 0 || N > CTE_VECTOR_MAX_LEN)
    {
        lea_abort("Invalid signature vector length read (N must be 1-15)");
    }

    size_t item_size = get_signature_item_size(TT);
    size_t total_data_size = N * item_size;

    CHECK_BOUNDS(decoder, 1 + total_data_size);

    decoder->position++;
    decoder->last_vector_count = N;

    const uint8_t *data_ptr = decoder->data + decoder->position;
    decoder->position += total_data_size;

    return data_ptr;
}


/**
 * @brief Reads and returns a 4-bit IxData Vector Index.
 * @param decoder A pointer to the decoder context.
 * @return The decoded 4-bit index value.
 * @note Internal helper function. Aborts on error.
 */
static uint8_t _cte_decoder_read_ixdata_vector_index(cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in read_ixdata_vector_index");
    }
    uint8_t header = _consume_ixdata_header(decoder, CTE_IXDATA_SUBTYPE_VECTOR_INDEX);

    uint8_t index = (header >> 2) & 0x0F;

    return index;
}


/**
 * @brief Reads and returns a ULEB128-encoded value from an IxData field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `uint64_t` value.
 * @note Internal helper function. Aborts on error.
 */
static uint64_t _cte_decoder_read_ixdata_uleb128(cte_decoder_t *decoder)
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
 * @brief Reads and returns an SLEB128-encoded value from an IxData field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `int64_t` value.
 * @note Internal helper function. Aborts on error.
 */
static int64_t _cte_decoder_read_ixdata_sleb128(cte_decoder_t *decoder)
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
 * @brief Reads a fixed-size `int8_t` from an IxData field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `int8_t` value.
 */
static int8_t _cte_decoder_read_ixdata_int8(cte_decoder_t *decoder)
{
    int8_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_INT8, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads a fixed-size `int16_t` from an IxData field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `int16_t` value.
 */
static int16_t _cte_decoder_read_ixdata_int16(cte_decoder_t *decoder)
{
    int16_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_INT16, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads a fixed-size `int32_t` from an IxData field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `int32_t` value.
 */
static int32_t _cte_decoder_read_ixdata_int32(cte_decoder_t *decoder)
{
    int32_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_INT32, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads a fixed-size `int64_t` from an IxData field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `int64_t` value.
 */
static int64_t _cte_decoder_read_ixdata_int64(cte_decoder_t *decoder)
{
    int64_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_INT64, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads a fixed-size `uint8_t` from an IxData field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `uint8_t` value.
 */
static uint8_t _cte_decoder_read_ixdata_uint8(cte_decoder_t *decoder)
{
    uint8_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_UINT8, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads a fixed-size `uint16_t` from an IxData field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `uint16_t` value.
 */
static uint16_t _cte_decoder_read_ixdata_uint16(cte_decoder_t *decoder)
{
    uint16_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_UINT16, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads a fixed-size `uint32_t` from an IxData field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `uint32_t` value.
 */
static uint32_t _cte_decoder_read_ixdata_uint32(cte_decoder_t *decoder)
{
    uint32_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_UINT32, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads a fixed-size `uint64_t` from an IxData field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `uint64_t` value.
 */
static uint64_t _cte_decoder_read_ixdata_uint64(cte_decoder_t *decoder)
{
    uint64_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_UINT64, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads a fixed-size `float` from an IxData field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `float` value.
 */
static float _cte_decoder_read_ixdata_float32(cte_decoder_t *decoder)
{
    float value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_FLOAT32, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads a fixed-size `double` from an IxData field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `double` value.
 */
static double _cte_decoder_read_ixdata_float64(cte_decoder_t *decoder)
{
    double value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_FLOAT64, sizeof(value), &value);
    return value;
}

/**
 * @brief Reads and returns a boolean constant from an IxData field.
 * @param decoder A pointer to the decoder context.
 * @return The decoded `bool` value.
 * @note Internal helper function. Aborts on error.
 */
static bool _cte_decoder_read_ixdata_boolean(cte_decoder_t *decoder)
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
 * @brief Reads the payload of a generic Vector Data field.
 *
 * Parses the header to determine the length, advances the decoder's position
 * past the header, and returns a pointer to the start of the payload.
 *
 * @param decoder A pointer to the decoder context.
 * @return A const pointer to the start of the payload data.
 * @note Internal helper function. Aborts on error.
 */
static const uint8_t *_cte_decoder_read_vector_data_payload(cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in read_vector_data_payload");
    }

    size_t header_size;
    size_t length = _parse_vector_data_header(decoder, &header_size);
    if (length == SIZE_MAX || header_size == 0)
    {
        lea_abort("Failed to parse vector data header before read (EOF or internal error)");
    }

    CHECK_BOUNDS(decoder, header_size + length);

    decoder->position += header_size;
    decoder->last_vector_data_len = length;

    const uint8_t *payload_ptr = decoder->data + decoder->position;

    decoder->position += length;

    return payload_ptr;
}

size_t cte_decoder_get_last_vector_count(const cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in get_last_vector_count");
    }
    return decoder->last_vector_count;
}

size_t cte_decoder_get_last_vector_data_payload_length(const cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in get_last_vector_data_payload_length");
    }
    return decoder->last_vector_data_len;
}

LEA_EXPORT(cte_decoder_run)
int cte_decoder_run(cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in run");
        return -1;
    }

    // The first peek validates the version byte
    int type = cte_decoder_peek_type(decoder);
    if (type == CTE_PEEK_EOF)
    {
        return 0; // Empty but valid
    }

    while ((type = cte_decoder_peek_type(decoder)) != CTE_PEEK_EOF)
    {
        switch (type)
        {
        // --- Vectors ---
        case CTE_PEEK_TYPE_PK_VECTOR_SIZE_0:
        case CTE_PEEK_TYPE_PK_VECTOR_SIZE_1:
        case CTE_PEEK_TYPE_PK_VECTOR_SIZE_2:
        case CTE_PEEK_TYPE_PK_VECTOR_SIZE_3:
        {
            const uint8_t *data = _cte_decoder_read_public_key_vector_data(decoder);
            size_t count = cte_decoder_get_last_vector_count(decoder);
            size_t item_size = get_public_key_size(type - CTE_PEEK_TYPE_PK_VECTOR_SIZE_0);
            __cte_data_handler(type, data, count * item_size);
            break;
        }
        case CTE_PEEK_TYPE_SIG_VECTOR_SIZE_0:
        case CTE_PEEK_TYPE_SIG_VECTOR_SIZE_1:
        case CTE_PEEK_TYPE_SIG_VECTOR_SIZE_2:
        case CTE_PEEK_TYPE_SIG_VECTOR_SIZE_3:
        {
            const uint8_t *data = _cte_decoder_read_signature_vector_data(decoder);
            size_t count = cte_decoder_get_last_vector_count(decoder);
            size_t item_size = get_signature_item_size(type - CTE_PEEK_TYPE_SIG_VECTOR_SIZE_0);
            __cte_data_handler(type, data, count * item_size);
            break;
        }
        // --- IxData ---
        case CTE_PEEK_TYPE_IXDATA_VECTOR_INDEX:
        {
            uint8_t val = _cte_decoder_read_ixdata_vector_index(decoder);
            __cte_data_handler(type, &val, sizeof(val));
            break;
        }
        case CTE_PEEK_TYPE_IXDATA_ULEB128:
        {
            uint64_t val = _cte_decoder_read_ixdata_uleb128(decoder);
            __cte_data_handler(type, &val, sizeof(val));
            break;
        }
        case CTE_PEEK_TYPE_IXDATA_SLEB128:
        {
            int64_t val = _cte_decoder_read_ixdata_sleb128(decoder);
            __cte_data_handler(type, &val, sizeof(val));
            break;
        }
        case CTE_PEEK_TYPE_IXDATA_CONST_FALSE:
        case CTE_PEEK_TYPE_IXDATA_CONST_TRUE:
        {
            bool val = _cte_decoder_read_ixdata_boolean(decoder);
            __cte_data_handler(type, &val, sizeof(val));
            break;
        }
        // --- Vector Data ---
        case CTE_PEEK_TYPE_VECTOR_SHORT:
        case CTE_PEEK_TYPE_VECTOR_EXTENDED:
        {
            const uint8_t *data = _cte_decoder_read_vector_data_payload(decoder);
            size_t len = cte_decoder_get_last_vector_data_payload_length(decoder);
            __cte_data_handler(type, data, len);
            break;
        }
        default:
            // For fixed-size data, we can create a generic handler
            if (type >= CTE_PEEK_TYPE_IXDATA_INT8 && type <= CTE_PEEK_TYPE_IXDATA_FLOAT64)
            {
                uint8_t temp_buf[8]; // Max size for float64
                size_t data_size = 0;
                switch (type)
                {
                case CTE_PEEK_TYPE_IXDATA_INT8:
                    *(int8_t *)temp_buf = _cte_decoder_read_ixdata_int8(decoder);
                    data_size = sizeof(int8_t);
                    break;
                case CTE_PEEK_TYPE_IXDATA_INT16:
                    *(int16_t *)temp_buf = _cte_decoder_read_ixdata_int16(decoder);
                    data_size = sizeof(int16_t);
                    break;
                case CTE_PEEK_TYPE_IXDATA_INT32:
                    *(int32_t *)temp_buf = _cte_decoder_read_ixdata_int32(decoder);
                    data_size = sizeof(int32_t);
                    break;
                case CTE_PEEK_TYPE_IXDATA_INT64:
                    *(int64_t *)temp_buf = _cte_decoder_read_ixdata_int64(decoder);
                    data_size = sizeof(int64_t);
                    break;
                case CTE_PEEK_TYPE_IXDATA_UINT8:
                    *(uint8_t *)temp_buf = _cte_decoder_read_ixdata_uint8(decoder);
                    data_size = sizeof(uint8_t);
                    break;
                case CTE_PEEK_TYPE_IXDATA_UINT16:
                    *(uint16_t *)temp_buf = _cte_decoder_read_ixdata_uint16(decoder);
                    data_size = sizeof(uint16_t);
                    break;
                case CTE_PEEK_TYPE_IXDATA_UINT32:
                    *(uint32_t *)temp_buf = _cte_decoder_read_ixdata_uint32(decoder);
                    data_size = sizeof(uint32_t);
                    break;
                case CTE_PEEK_TYPE_IXDATA_UINT64:
                    *(uint64_t *)temp_buf = _cte_decoder_read_ixdata_uint64(decoder);
                    data_size = sizeof(uint64_t);
                    break;
                case CTE_PEEK_TYPE_IXDATA_FLOAT32:
                    *(float *)temp_buf = _cte_decoder_read_ixdata_float32(decoder);
                    data_size = sizeof(float);
                    break;
                case CTE_PEEK_TYPE_IXDATA_FLOAT64:
                    *(double *)temp_buf = _cte_decoder_read_ixdata_float64(decoder);
                    data_size = sizeof(double);
                    break;
                }
                __cte_data_handler(type, temp_buf, data_size);
            }
            else
            {
                lea_abort("Unknown or unhandled peek type in run loop");
                return -1;
            }
            break;
        }
    }
    return 0;
}

