#include "enclave_t.h"
#include "string.h"
#include "keys.h"
#include <map>
#include "sgx_thread.h"

#define MAX_RETRIES 100

#define MAC_KEY_SIZE 16
#define MAC_SIZE 16
#define IV_SIZE 12
#define EC_DERIVATION_BUFFER_SIZE(label_length) ((label_length) +4)

sgx_ecc_state_handle_t *p_ecc_handle = NULL;

keys_db_item_t keys_db;

bool initiated_ra = false;

/* Internal functions */

sgx_status_t generate_handle( )
{
    sgx_status_t ret;

    p_ecc_handle = ( sgx_ecc_state_handle_t * ) malloc( sizeof( sgx_ecc_state_handle_t ) );

    int retries = MAX_RETRIES;
    while ( retries-- && ( ( ret = sgx_ecc256_open_context( p_ecc_handle ) ) != SGX_SUCCESS ) ) continue;

    return ret;
}

sgx_status_t generate_keys( )
{
    sgx_status_t ret = SGX_SUCCESS;

    ret = generate_handle( );
    if ( SGX_SUCCESS != ret ) return ret;

    int retries = MAX_RETRIES;
    while ( retries-- && !initiated_ra )
    {
        ret = sgx_ecc256_create_key_pair( &keys_db.b, &keys_db.g_b, *p_ecc_handle );
        initiated_ra = SGX_SUCCESS == ret;
    }
    return ret;
}

sgx_status_t enclave_get_gb( sgx_ec256_public_t *p_gb_out )
{
    sgx_status_t ret = SGX_SUCCESS;
    if ( !initiated_ra ) ret = generate_keys( );
    if ( SGX_SUCCESS != ret ) return ret;

    memcpy( p_gb_out, &keys_db.g_b, sizeof( sgx_ec256_public_t ) );
    return ret;
}

sgx_status_t compute_cmac( sgx_cmac_128bit_key_t *cmac_key,
                                   uint8_t               *p_src,
                                   size_t                 src_len,
                                   sgx_cmac_128bit_tag_t *p_mac )
{
    sgx_status_t ret = SGX_SUCCESS;
    ret = sgx_rijndael128_cmac_msg( cmac_key, p_src, src_len, p_mac );
    return ret;
}

sgx_status_t derive_key(
    const sgx_ec256_dh_shared_t* shared_key,
    const char* label,
    uint32_t label_length,
    sgx_ec_key_128bit_t* derived_key )
{
    sgx_status_t se_ret = SGX_SUCCESS, status = SGX_SUCCESS;
    uint8_t cmac_key[ MAC_KEY_SIZE ];
    sgx_ec_key_128bit_t key_derive_key;
    if ( !shared_key || !derived_key || !label )
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    /*check integer overflow */
    if ( label_length > EC_DERIVATION_BUFFER_SIZE( label_length ) )
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    memset( cmac_key, 0, MAC_KEY_SIZE );
    se_ret = compute_cmac(
        ( sgx_cmac_128bit_key_t * )cmac_key,
        ( uint8_t* )shared_key,
        sizeof( sgx_ec256_dh_shared_t ),
        ( sgx_cmac_128bit_tag_t * ) &key_derive_key );
    if ( SGX_SUCCESS != se_ret )
    {
        memset( &key_derive_key, 0, sizeof(key_derive_key) );
        return se_ret;
    }
    /* derivation_buffer = counter(0x01) || label || 0x00 || output_key_len(0x0080) */
    uint32_t derivation_buffer_length = EC_DERIVATION_BUFFER_SIZE( label_length );
    uint8_t *p_derivation_buffer = ( uint8_t * ) malloc( derivation_buffer_length );
    if ( p_derivation_buffer == NULL )
    {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    memset( p_derivation_buffer, 0, derivation_buffer_length );

    /*counter = 0x01 */
    p_derivation_buffer[ 0 ] = 0x01;
    /*label*/
    memcpy( &p_derivation_buffer[ 1 ], label, label_length );
    /*output_key_len=0x0080*/
    uint16_t *key_len = ( uint16_t * ) &p_derivation_buffer[ derivation_buffer_length - 2 ];
    *key_len = 0x0080;

    se_ret = compute_cmac(
        ( sgx_cmac_128bit_key_t * ) &key_derive_key,
        p_derivation_buffer,
        derivation_buffer_length,
        ( sgx_cmac_128bit_tag_t * ) derived_key );
    memset( &key_derive_key, 0, sizeof( key_derive_key ) );
    free( p_derivation_buffer );
    return se_ret;
}

/* ECalls*/

sgx_status_t enclave_ra_init( sgx_ec256_public_t *p_gb_out )
{
    sgx_status_t ret = SGX_SUCCESS;
    ret = enclave_get_gb( p_gb_out );
    return ret;
}

void enclave_set_ga( sgx_ec256_public_t *p_ga_in, size_t len )
{
    memcpy( &keys_db.g_a, p_ga_in, sizeof( sgx_ec256_public_t ) );
}

sgx_status_t enclave_derive_keys( )
{
    sgx_status_t ret = SGX_SUCCESS;

    sgx_ec256_dh_shared_t dh_key;
    memset( &dh_key, 0, sizeof( sgx_ec256_dh_shared_t ) );

    int retries = MAX_RETRIES;
    while ( retries-- && ( ret = sgx_ecc256_compute_shared_dhkey( &keys_db.b,
                                                                  &keys_db.g_a,
                                                                  &dh_key,
                                                                  *p_ecc_handle ) ) != SGX_SUCCESS ) continue;
    if ( SGX_SUCCESS != ret ) return ret;

    ret = derive_key( &dh_key, "SMK", ( uint32_t )( sizeof( "SMK" ) -1 ), &keys_db.smk_key );
    if ( SGX_SUCCESS != ret ) return ret;

    ret = derive_key( &dh_key, "MK", ( uint32_t )( sizeof( "MK" ) -1 ), &keys_db.mk_key);
    if ( SGX_SUCCESS != ret ) return ret;

    ret = derive_key( &dh_key, "SK", ( uint32_t )( sizeof( "SK" ) -1 ), &keys_db.sk_key);
    if ( SGX_SUCCESS != ret ) return ret;

    ret = derive_key( &dh_key, "VK", ( uint32_t )( sizeof( "VK" ) -1 ), &keys_db.vk_key);

    return ret;
}

sgx_status_t enclave_get_sign_gb_ga( sgx_ec256_signature_t *p_sign_gb_ga )
{
    sgx_status_t ret = SGX_SUCCESS;

    size_t gb_ga_size = 2 * sizeof( sgx_ec256_public_t );
#ifdef DEBUG_VARIABLE
    emit_debug( "gb_ga inside:" );
    print_byte_array( &keys_db.g_b, 2*sizeof(sgx_ec256_public_t ) );
#endif
    ret = sgx_ecdsa_sign( ( const uint8_t * ) &keys_db.g_b, gb_ga_size, &keys_db.b, p_sign_gb_ga, *p_ecc_handle );
    return ret;
}

sgx_status_t enclave_compute_msg2_mac( uint8_t               *p_src,
                                       size_t                 len,
                                       sgx_cmac_128bit_key_t *p_mac_out )
{
    sgx_status_t ret = SGX_SUCCESS;
    ret = compute_cmac( ( sgx_cmac_128bit_key_t * ) &keys_db.smk_key,
                        p_src, len, p_mac_out );
    return ret;

}

sgx_status_t enclave_encrypt( uint8_t *data, size_t data_len, uint8_t *buffer, size_t buffer_len )
{
    if ( sgx_read_rand( buffer, IV_SIZE ) != SGX_SUCCESS )
    {
        return SGX_ERROR_UNEXPECTED;
    }

    sgx_aes_gcm_128bit_tag_t mac;

    emit_debug( "SK key:" );
    print_byte_array( &keys_db.sk_key, sizeof( sgx_ec_key_128bit_t ) );

    sgx_status_t result = sgx_rijndael128GCM_encrypt( &keys_db.sk_key, data, data_len, buffer + IV_SIZE + MAC_SIZE, buffer, IV_SIZE, NULL, 0, ( sgx_aes_gcm_128bit_tag_t * ) ( buffer + IV_SIZE ) );

    return result;
}
