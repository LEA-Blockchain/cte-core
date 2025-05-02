#include "decoder.h"
#include <stdlea.h>

// Helper Macros
#define CHECK_BOUNDS(decoder, needed)                     \
    if ((decoder)->position + (needed) > (decoder)->size) \
    {                                                     \
        lea_abort("Read past end of buffer");             \
    }

// Check bounds without aborting (peek)
#define CHECK_BOUNDS_PEEK(decoder, needed) (((decoder)->position + (needed)) <= (decoder)->size)

#define CHECK_TAG(header, expected_tag)              \
    if (((header) & CTE_TAG_MASK) != (expected_tag)) \
    {                                                \
        lea_abort("Unexpected field tag");           \
    }

#define CHECK_TAG_PEEK(header, expected_tag) (((header) & CTE_TAG_MASK) == (expected_tag))

#define CHECK_PADDING_ZERO(value, mask, context)        \
    if (((value) & (mask)) != 0)                        \
    {                                                   \
        lea_abort("Non-zero padding bits in " context); \
    }

// Check padding (peek)
#define CHECK_PADDING_ZERO_PEEK(value, mask) (((value) & (mask)) == 0)

// Internal
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

static uint8_t _consume_ixdata_header(cte_decoder_t *decoder, uint8_t expected_subtype)
{
    CHECK_BOUNDS(decoder, 1);
    uint8_t header = decoder->data[decoder->position]; // Peek first

    // Explicitly check the main tag first
    CHECK_TAG(header, CTE_TAG_IXDATA_FIELD);

    // Now check the subtype
    uint8_t SS = header & CTE_IXDATA_SUBTYPE_MASK;
    if (SS != expected_subtype)
    {
        lea_abort("Unexpected IxData subtype");
    }

    // Advance position only after checks pass
    decoder->position++;
    return header;
}

static void _decode_uleb128(cte_decoder_t *decoder, uint64_t *out_value)
{
    uint64_t result = 0;
    int shift = 0;
    uint8_t byte;
    const size_t max_bytes = 10; // Max bytes for 64-bit ULEB128 (ceil(64/7))

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

static void _decode_sleb128(cte_decoder_t *decoder, int64_t *out_value)
{
    int64_t result = 0;
    int shift = 0;
    uint8_t byte;
    const size_t max_bytes = 10; // Max bytes for 64-bit SLEB128

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
        return SIZE_MAX; // Unreachable
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

    return decoder;
}

LEA_EXPORT(cte_decoder_load)
uint8_t *cte_decoder_load(cte_decoder_t *decoder)
{
    return decoder->data;
    // uint8_t version_byte = decoder->data[decoder->position++];
    // if (version_byte != CTE_VERSION_BYTE)
    //{
    //     lea_abort("Invalid version byte");
    // }
    //  difficult to check version here. maybe in peek?
}

LEA_EXPORT(cte_decoder_reset)
void cte_decoder_reset(cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in reset");
    }
    decoder->position = 1; // Set after version byte
}

LEA_EXPORT(cte_decoder_peek_tag)
int cte_decoder_peek_tag(cte_decoder_t *decoder)
{
    // Check version
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
        return -1;
    }
    return header_byte & CTE_TAG_MASK;
}

LEA_EXPORT(cte_decoder_peek_public_key_list_count)
uint8_t cte_decoder_peek_public_key_list_count(const cte_decoder_t *decoder)
{
    int header_byte = _cte_decoder_peek_header_byte(decoder);
    if (header_byte == -1)
        return CTE_PEEK_EOF;

    if (!CHECK_TAG_PEEK(header_byte, CTE_TAG_PUBLIC_KEY_LIST))
    {
        lea_abort("Peeked field is not a Public Key List");
    }

    uint8_t N = (header_byte >> 2) & 0x0F;
    if (N == 0 || N > CTE_LIST_MAX_LEN)
    {
        lea_abort("Invalid public key list length in peek (N must be 1-15)");
    }
    return N;
}

LEA_EXPORT(cte_decoder_peek_public_key_list_type)
uint8_t cte_decoder_peek_public_key_list_type(const cte_decoder_t *decoder)
{
    int header_byte = _cte_decoder_peek_header_byte(decoder);
    if (header_byte == -1)
        return CTE_PEEK_EOF;

    if (!CHECK_TAG_PEEK(header_byte, CTE_TAG_PUBLIC_KEY_LIST))
    {
        lea_abort("Peeked field is not a Public Key List");
    }

    uint8_t TT = header_byte & CTE_CRYPTO_TYPE_MASK;
    return TT;
}

LEA_EXPORT(cte_decoder_read_public_key_list_data)
const uint8_t *cte_decoder_read_public_key_list_data(cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in read_public_key_list_data");
    }
    CHECK_BOUNDS(decoder, 1);                          // Need header
    uint8_t header = decoder->data[decoder->position]; // Read header (don't advance yet)

    CHECK_TAG(header, CTE_TAG_PUBLIC_KEY_LIST);

    uint8_t N = (header >> 2) & 0x0F;
    uint8_t TT = header & CTE_CRYPTO_TYPE_MASK;

    if (N == 0 || N > CTE_LIST_MAX_LEN)
    {
        lea_abort("Invalid public key list length read (N must be 1-15)");
    }

    size_t item_size = get_public_key_size(TT); // Aborts on invalid TT
    size_t total_data_size = N * item_size;

    CHECK_BOUNDS(decoder, 1 + total_data_size);

    decoder->position++; // Advance past header

    const uint8_t *data_ptr = decoder->data + decoder->position;
    decoder->position += total_data_size; // Advance past data

    return data_ptr;
}

LEA_EXPORT(cte_decoder_peek_signature_list_count)
uint8_t cte_decoder_peek_signature_list_count(const cte_decoder_t *decoder)
{
    int header_byte = _cte_decoder_peek_header_byte(decoder);
    if (header_byte == -1)
        return CTE_PEEK_EOF;

    if (!CHECK_TAG_PEEK(header_byte, CTE_TAG_SIGNATURE_LIST))
    {
        lea_abort("Peeked field is not a Signature List");
    }

    uint8_t N = (header_byte >> 2) & 0x0F;
    if (N == 0 || N > CTE_LIST_MAX_LEN)
    {
        lea_abort("Invalid signature list length in peek (N must be 1-15)");
    }
    return N;
}

LEA_EXPORT(cte_decoder_peek_signature_list_type)
uint8_t cte_decoder_peek_signature_list_type(const cte_decoder_t *decoder)
{
    int header_byte = _cte_decoder_peek_header_byte(decoder);
    if (header_byte == -1)
        return CTE_PEEK_EOF;

    if (!CHECK_TAG_PEEK(header_byte, CTE_TAG_SIGNATURE_LIST))
    {
        lea_abort("Peeked field is not a Signature List");
    }
    uint8_t TT = header_byte & CTE_CRYPTO_TYPE_MASK;
    return TT;
}

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

    size_t item_size = get_signature_item_size(TT); // Aborts on invalid TT
    size_t total_data_size = N * item_size;

    CHECK_BOUNDS(decoder, 1 + total_data_size); // Check header + data

    decoder->position++; // Advance past header

    const uint8_t *data_ptr = decoder->data + decoder->position;
    decoder->position += total_data_size; // Advance past data

    return data_ptr;
}

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

LEA_EXPORT(cte_decoder_read_ixdata_int8)
int8_t cte_decoder_read_ixdata_int8(cte_decoder_t *decoder)
{
    int8_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_INT8, sizeof(value), &value);
    return value;
}
LEA_EXPORT(cte_decoder_read_ixdata_int16)
int16_t cte_decoder_read_ixdata_int16(cte_decoder_t *decoder)
{
    int16_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_INT16, sizeof(value), &value);
    return value;
}
LEA_EXPORT(cte_decoder_read_ixdata_int32)
int32_t cte_decoder_read_ixdata_int32(cte_decoder_t *decoder)
{
    int32_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_INT32, sizeof(value), &value);
    return value;
}
LEA_EXPORT(cte_decoder_read_ixdata_int64)
int64_t cte_decoder_read_ixdata_int64(cte_decoder_t *decoder)
{
    int64_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_INT64, sizeof(value), &value);
    return value;
}
LEA_EXPORT(cte_decoder_read_ixdata_uint8)
uint8_t cte_decoder_read_ixdata_uint8(cte_decoder_t *decoder)
{
    uint8_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_UINT8, sizeof(value), &value);
    return value;
}
LEA_EXPORT(cte_decoder_read_ixdata_uint16)
uint16_t cte_decoder_read_ixdata_uint16(cte_decoder_t *decoder)
{
    uint16_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_UINT16, sizeof(value), &value);
    return value;
}
LEA_EXPORT(cte_decoder_read_ixdata_uint32)
uint32_t cte_decoder_read_ixdata_uint32(cte_decoder_t *decoder)
{
    uint32_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_UINT32, sizeof(value), &value);
    return value;
}
LEA_EXPORT(cte_decoder_read_ixdata_uint64)
uint64_t cte_decoder_read_ixdata_uint64(cte_decoder_t *decoder)
{
    uint64_t value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_UINT64, sizeof(value), &value);
    return value;
}
LEA_EXPORT(cte_decoder_read_ixdata_float32)
float cte_decoder_read_ixdata_float32(cte_decoder_t *decoder)
{
    float value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_FLOAT32, sizeof(value), &value);
    return value;
}
LEA_EXPORT(cte_decoder_read_ixdata_float64)
double cte_decoder_read_ixdata_float64(cte_decoder_t *decoder)
{
    double value;
    _read_fixed_data(decoder, CTE_IXDATA_FIXED_TYPE_FLOAT64, sizeof(value), &value);
    return value;
}

LEA_EXPORT(cte_decoder_read_ixdata_boolean)
bool cte_decoder_read_ixdata_boolean(cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in read_ixdata_constant");
    }
    uint8_t header = _consume_ixdata_header(decoder, CTE_IXDATA_SUBTYPE_CONSTANT);
    uint8_t XXXX = (header >> 2) & 0x0F; // Extract 4 bits for Value Code

    if (XXXX == CTE_IXDATA_CONST_VAL_FALSE)
    {
        return false; // Use value from cte.h
    }
    else if (XXXX == CTE_IXDATA_CONST_VAL_TRUE)
    {
        return true; // Use value from cte.h
    }
    else
    {
        lea_abort("Reserved IxData Constant value code encountered");
        return false; // Unreachable
    }
}

LEA_EXPORT(cte_decoder_peek_command_data_length)
size_t cte_decoder_peek_command_data_length(const cte_decoder_t *decoder)
{
    if (!decoder)
    {
        lea_abort("Null decoder handle in peek_command_data_length");
    }
    size_t header_size;
    return _parse_command_data_header(decoder, &header_size);
}

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

    const uint8_t *payload_ptr = decoder->data + decoder->position;

    decoder->position += length;

    return payload_ptr;
}
