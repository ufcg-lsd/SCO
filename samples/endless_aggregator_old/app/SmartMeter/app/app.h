#ifndef _SMART_METER_APP_H
#define _SMART_METER_APP_H

#include "sgx_key_exchange.h"
#define MAX_ACTIVE_POWER 250

typedef struct _smart_meter_db_item_t
{
    sgx_ec256_public_t     g_a;
    sgx_ec256_public_t     g_b;
    sgx_ra_key_128_t       vk_key;// Shared secret key for the REPORT_DATA
    sgx_ra_key_128_t       mk_key;// Shared secret key for generating MAC's
    sgx_ra_key_128_t       sk_key;// Shared secret key for encryption
    sgx_ra_key_128_t       smk_key;// Used only for SIGMA protocol
    sgx_ec256_private_t    b;
    sgx_ps_sec_prop_desc_t ps_sec_prop;
} smart_meter_db_item_t;

typedef enum _sp_derive_key_type_t
{
    SP_DERIVE_KEY_SMK = 0,
    SP_DERIVE_KEY_SK,
    SP_DERIVE_KEY_MK,
    SP_DERIVE_KEY_VK,
} sp_derive_key_type_t;

#endif
