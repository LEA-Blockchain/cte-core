#include "decoder.h"
#include "encoder.h"
#include <stdio.h>

#define BUFFER_SIZE 2048

void print_hex(const char *label, const uint8_t *data, size_t size)
{
    if (data == NULL && size > 0)
    {
        printf("%s (%zu bytes): <NULL DATA>\n", label, size);
        return;
    }
    if (size == 0)
    {
        printf("%s (0 bytes): <EMPTY>\n", label);
        return;
    }
    printf("%s (%zu bytes): ", label, size);
    for (size_t i = 0; i < size; ++i)
    {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int main()
{
    printf("CTE Encoder/Decoder Native Test\n");

    cte_encoder_t *enc = cte_encoder_init(BUFFER_SIZE);

    printf("Encoding:\n");

    uint8_t key_count_enc = 2;
    uint8_t key_type_enc = CTE_CRYPTO_TYPE_ED25519;
    uint8_t dummy_keys[2 * CTE_PUBKEY_SIZE_ED25519];
    for (size_t i = 0; i < sizeof(dummy_keys); ++i)
        dummy_keys[i] = (uint8_t)(0xAA + i);
    void *key_ptr = cte_encoder_begin_public_key_list(enc, key_count_enc, key_type_enc);
    memcpy(key_ptr, dummy_keys, sizeof(dummy_keys));
    printf("Encoded Public Key List (Type: %u, Count: %u).\n", key_type_enc, key_count_enc);

    cte_encoder_write_ixdata_index_reference(enc, 1); // Index 1 (valid for key list count 2)
    printf("Encoded IxData Legacy Index (1 - for PubKey List).\n");

    uint8_t sig_count_enc = 1;
    uint8_t sig_type_enc = CTE_CRYPTO_TYPE_SLH_DSA_128F;
    uint8_t dummy_sig_hash[CTE_SIGNATURE_HASH_SIZE_PQC];
    for (size_t i = 0; i < sizeof(dummy_sig_hash); ++i)
        dummy_sig_hash[i] = (uint8_t)(0xBB + i);
    void *sig_ptr = cte_encoder_begin_signature_list(enc, sig_count_enc, sig_type_enc);
    memcpy(sig_ptr, dummy_sig_hash, sizeof(dummy_sig_hash));
    printf("Encoded Signature List (Type: %u, Count: %u).\n", sig_type_enc, sig_count_enc);

    cte_encoder_write_ixdata_index_reference(enc, 0); // Index 0 (valid for sig list count 1)
    printf("Encoded IxData Legacy Index (0 - for Sig List).\n");

    uint64_t uleb_val_enc = 123456;
    cte_encoder_write_ixdata_uleb128(enc, uleb_val_enc);
    printf("Encoded IxData ULEB128 (%llu).\n", (unsigned long long)uleb_val_enc);
    int64_t sleb_val_enc = -78910;
    cte_encoder_write_ixdata_sleb128(enc, sleb_val_enc);
    printf("Encoded IxData SLEB128 (%lld).\n", (long long)sleb_val_enc);
    int32_t i32_val_enc = -1000;
    cte_encoder_write_ixdata_int32(enc, i32_val_enc);
    printf("Encoded IxData Int32 (%d).\n", i32_val_enc);
    uint64_t u64_val_enc = 9876543210ULL;
    cte_encoder_write_ixdata_uint64(enc, u64_val_enc);
    printf("Encoded IxData Uint64 (%llu).\n", (unsigned long long)u64_val_enc);
    float f32_val_enc = 3.14159f;
    cte_encoder_write_ixdata_float32(enc, f32_val_enc);
    printf("Encoded IxData Float32 (%f).\n", f32_val_enc);
    cte_encoder_write_ixdata_boolean(enc, true);
    printf("Encoded IxData Boolean (true).\n");
    cte_encoder_write_ixdata_boolean(enc, false);
    printf("Encoded IxData Boolean (false).\n");

    const char *short_cmd_enc = "Short payload";
    size_t short_len_enc = strlen(short_cmd_enc);
    void *cmd_ptr_short = cte_encoder_begin_command_data(enc, short_len_enc);
    memcpy(cmd_ptr_short, short_cmd_enc, short_len_enc);
    printf("Encoded Command Data (Short, Len: %zu).\n", short_len_enc);

    char long_cmd_enc[200];
    memset(long_cmd_enc, 'L', sizeof(long_cmd_enc));
    long_cmd_enc[199] = '\0';
    size_t long_len_enc = 150;
    void *cmd_ptr_long = cte_encoder_begin_command_data(enc, long_len_enc);
    memcpy(cmd_ptr_long, long_cmd_enc, long_len_enc);
    printf("Encoded Command Data (Extended, Len: %zu).\n", long_len_enc);

    const uint8_t *encoded_data = cte_encoder_get_data(enc);
    size_t encoded_size = cte_encoder_get_size(enc);
    printf("\nTotal Encoded Size: %zu bytes\n", encoded_size);
    print_hex("Encoded Data", encoded_data, encoded_size);

    printf("Decoding\n");
    cte_decoder_t *dec = cte_decoder_init(encoded_size);
    printf("Decoder initialized. Position: %zu\n", dec->position);

    uint8_t *loadPtr = cte_decoder_load(dec);
    memcpy(loadPtr, encoded_data, encoded_size);

    int tag;
    tag = cte_decoder_peek_tag(dec);
    if (tag != CTE_TAG_PUBLIC_KEY_LIST)
        printf("ERROR: Expected PubKey List Tag!\n");
    uint8_t key_count_dec = cte_decoder_peek_public_key_list_count(dec);
    uint8_t key_type_dec = cte_decoder_peek_public_key_list_type(dec);
    printf("Peeked PubKey List (Type: %u, Count: %u) at pos %zu.\n", key_type_dec, key_count_dec, dec->position);
    if (key_count_dec != key_count_enc || key_type_dec != key_type_enc)
        printf("ERROR: Peeked PubKey List mismatch!\n");
    const uint8_t *keys_dec = cte_decoder_read_public_key_list_data(dec);
    printf("Read PubKey List. New pos: %zu.\n", dec->position);
    if (memcmp(keys_dec, dummy_keys, sizeof(dummy_keys)) != 0)
        printf("ERROR: Decoded keys mismatch!\n");

    tag = cte_decoder_peek_tag(dec);
    if (tag != CTE_TAG_IXDATA_FIELD)
        printf("ERROR: Expected IxData Tag (after PubKey)!\n");
    uint8_t index1_dec = cte_decoder_read_ixdata_index_reference(dec);
    printf("Decoded IxData Legacy Index (for PubKey): %u. New pos: %zu.\n", index1_dec, dec->position);
    if (index1_dec != 1)
        printf("ERROR: Legacy Index 1 mismatch!\n");

    tag = cte_decoder_peek_tag(dec);
    if (tag != CTE_TAG_SIGNATURE_LIST)
        printf("ERROR: Expected Sig List Tag!\n");
    uint8_t sig_count_dec = cte_decoder_peek_signature_list_count(dec);
    uint8_t sig_type_dec = cte_decoder_peek_signature_list_type(dec);
    printf("Peeked Sig List (Type: %u, Count: %u) at pos %zu.\n", sig_type_dec, sig_count_dec, dec->position);
    if (sig_count_dec != sig_count_enc || sig_type_dec != sig_type_enc)
        printf("ERROR: Peeked Sig List mismatch!\n");
    const uint8_t *sigs_dec = cte_decoder_read_signature_list_data(dec);
    printf("Read Sig List. New pos: %zu.\n", dec->position);
    if (memcmp(sigs_dec, dummy_sig_hash, sizeof(dummy_sig_hash)) != 0)
        printf("ERROR: Decoded sig hash mismatch!\n");

    tag = cte_decoder_peek_tag(dec);
    if (tag != CTE_TAG_IXDATA_FIELD)
        printf("ERROR: Expected IxData Tag (after Sig)!\n");
    uint8_t index0_dec = cte_decoder_read_ixdata_index_reference(dec);
    printf("Decoded IxData Legacy Index (for Sig): %u. New pos: %zu.\n", index0_dec, dec->position);
    if (index0_dec != 0)
        printf("ERROR: Legacy Index 0 mismatch!\n");

    tag = cte_decoder_peek_tag(dec);
    if (tag != CTE_TAG_IXDATA_FIELD)
        printf("ERROR: Expected IxData Tag (ULEB)!\n");
    uint64_t uleb_val_dec = cte_decoder_read_ixdata_uleb128(dec);
    printf("Decoded IxData ULEB128: %llu. New pos: %zu.\n", (unsigned long long)uleb_val_dec, dec->position);
    if (uleb_val_dec != uleb_val_enc)
        printf("ERROR: ULEB128 mismatch!\n");

    tag = cte_decoder_peek_tag(dec);
    if (tag != CTE_TAG_IXDATA_FIELD)
        printf("ERROR: Expected IxData Tag (SLEB)!\n");
    int64_t sleb_val_dec = cte_decoder_read_ixdata_sleb128(dec);
    printf("Decoded IxData SLEB128: %lld. New pos: %zu.\n", (long long)sleb_val_dec, dec->position);
    if (sleb_val_dec != sleb_val_enc)
        printf("ERROR: SLEB128 mismatch!\n");

    tag = cte_decoder_peek_tag(dec);
    if (tag != CTE_TAG_IXDATA_FIELD)
        printf("ERROR: Expected IxData Tag (Int32)!\n");
    int32_t i32_val_dec = cte_decoder_read_ixdata_int32(dec);
    printf("Decoded IxData Int32: %d. New pos: %zu.\n", i32_val_dec, dec->position);
    if (i32_val_dec != i32_val_enc)
        printf("ERROR: Int32 mismatch!\n");

    tag = cte_decoder_peek_tag(dec);
    if (tag != CTE_TAG_IXDATA_FIELD)
        printf("ERROR: Expected IxData Tag (Uint64)!\n");
    uint64_t u64_val_dec = cte_decoder_read_ixdata_uint64(dec);
    printf("Decoded IxData Uint64: %llu. New pos: %zu.\n", (unsigned long long)u64_val_dec, dec->position);
    if (u64_val_dec != u64_val_enc)
        printf("ERROR: Uint64 mismatch!\n");

    tag = cte_decoder_peek_tag(dec);
    if (tag != CTE_TAG_IXDATA_FIELD)
        printf("ERROR: Expected IxData Tag (Float32)!\n");
    float f32_val_dec = cte_decoder_read_ixdata_float32(dec);
    printf("Decoded IxData Float32: %f. New pos: %zu.\n", f32_val_dec, dec->position);
    if (f32_val_dec != f32_val_enc)
        printf("ERROR: Float32 mismatch!\n");

    tag = cte_decoder_peek_tag(dec);
    if (tag != CTE_TAG_IXDATA_FIELD)
        printf("ERROR: Expected IxData Tag (Const True)!\n");
    bool const_true_dec = cte_decoder_read_ixdata_boolean(dec);
    printf("Decoded IxData Constant: %d. New pos: %zu.\n", const_true_dec, dec->position);
    if (const_true_dec != true)
        printf("ERROR: Constant True mismatch!\n");

    tag = cte_decoder_peek_tag(dec);
    if (tag != CTE_TAG_IXDATA_FIELD)
        printf("ERROR: Expected IxData Tag (Const False)!\n");
    bool const_false_dec = cte_decoder_read_ixdata_boolean(dec);
    printf("Decoded IxData Constant: %d. New pos: %zu.\n", const_false_dec, dec->position);
    if (const_false_dec != false)
        printf("ERROR: Constant False mismatch!\n");

    tag = cte_decoder_peek_tag(dec);
    if (tag != CTE_TAG_COMMAND_DATA)
        printf("ERROR: Expected Command Data Tag (Short)!\n");
    size_t short_len_dec_peek = cte_decoder_peek_command_data_length(dec);
    printf("Peeked Command Data Length (Short): %zu at pos %zu.\n", short_len_dec_peek, dec->position);
    if (short_len_dec_peek != short_len_enc)
        printf("ERROR: Peeked short cmd length mismatch!\n");
    const uint8_t *short_cmd_dec = cte_decoder_read_command_data_payload(dec);
    printf("Read Command Data (Short). New pos: %zu.\n", dec->position);
    if (memcmp(short_cmd_dec, short_cmd_enc, short_len_enc) != 0)
        printf("ERROR: Decoded short cmd mismatch!\n");

    tag = cte_decoder_peek_tag(dec);
    if (tag != CTE_TAG_COMMAND_DATA)
        printf("ERROR: Expected Command Data Tag (Extended)!\n");
    size_t long_len_dec_peek = cte_decoder_peek_command_data_length(dec);
    printf("Peeked Command Data Length (Extended): %zu at pos %zu.\n", long_len_dec_peek, dec->position);
    if (long_len_dec_peek != long_len_enc)
        printf("ERROR: Peeked long cmd length mismatch!\n");
    const uint8_t *long_cmd_dec = cte_decoder_read_command_data_payload(dec);
    printf("Read Command Data (Extended). New pos: %zu.\n", dec->position);
    if (memcmp(long_cmd_dec, long_cmd_enc, long_len_enc) != 0)
        printf("ERROR: Decoded long cmd mismatch!\n");

    if (dec->position != encoded_size)
    {
        printf("ERROR: Final decoder position (%zu) does not match encoded size (%zu)!\n", dec->position, encoded_size);
    }
    else
    {
        printf("\nSuccessfully decoded all fields. Final position matches encoded size.\n");
    }

    printf("\n--- Test Complete ---\n");
    return 0;
}
