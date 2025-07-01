#include "cte.h"
#include <stdlea.h>

/**
 * @brief Gets the size in bytes of a public key for a given crypto type.
 * @param type_code The crypto type code (e.g., CTE_CRYPTO_TYPE_ED25519).
 * @return The size of the public key in bytes.
 * @note This function will abort via `lea_abort` if an invalid type code is provided.
 */
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

/**
 * @brief Gets the size in bytes of a signature list item for a given crypto type.
 *
 * For Ed25519, this is the full signature size. For PQC schemes like SLH-DSA,
 * this is the size of the signature's hash.
 *
 * @param type_code The crypto type code (e.g., CTE_CRYPTO_TYPE_ED25519).
 * @return The size of the signature item in bytes.
 * @note This function will abort via `lea_abort` if an invalid type code is provided.
 */
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
