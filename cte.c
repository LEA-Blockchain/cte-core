#include "cte.h"
#include <stdlea.h>

LEA_EXPORT(get_public_key_size)
size_t get_public_key_size(uint8_t type_code)
{
    switch (type_code)
    {
    case CTE_CRYPTO_TYPE_ED25519:
        return CTE_PUBKEY_SIZE_ED25519;
    case CTE_CRYPTO_TYPE_SLH_DSA_128F:
        return CTE_PUBKEY_SIZE_SLH_128F;
    case CTE_CRYPTO_TYPE_SLH_DSA_192F:
        return CTE_PUBKEY_SIZE_SLH_192F;
    case CTE_CRYPTO_TYPE_SLH_DSA_256F:
        return CTE_PUBKEY_SIZE_SLH_256F;
    default:
        lea_abort("Invalid public key type code");
    }
}

LEA_EXPORT(get_signature_item_size)
size_t get_signature_item_size(uint8_t type_code)
{
    switch (type_code)
    {
    case CTE_CRYPTO_TYPE_ED25519:
        return CTE_SIGNATURE_SIZE_ED25519;
    case CTE_CRYPTO_TYPE_SLH_DSA_128F:
    case CTE_CRYPTO_TYPE_SLH_DSA_192F:
    case CTE_CRYPTO_TYPE_SLH_DSA_256F:
        return CTE_SIGNATURE_HASH_SIZE_PQC;
    default:
        lea_abort("Invalid signature type code");
    }
}
