#ifndef _KEY_TYPES_H
#define _KEY_TYPES_H

#include "sgx_key_exchange.h"

typedef struct _keys_db_item_t
{
    sgx_ec256_public_t     g_b;
    sgx_ec256_public_t     g_a;
    sgx_ra_key_128_t       vk_key;// Shared secret key for the REPORT_DATA
    sgx_ra_key_128_t       mk_key;// Shared secret key for generating MAC's
    sgx_ra_key_128_t       sk_key;// Shared secret key for encryption
    sgx_ra_key_128_t       smk_key;// Used only for SIGMA protocol
    sgx_ps_sec_prop_desc_t ps_sec_prop;
} keys_db_item_t;

#endif
