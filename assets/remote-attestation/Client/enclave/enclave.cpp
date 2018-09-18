#include "enclave_t.h"
#include "string.h"
#include "sgx_tkey_exchange.h"

#define IV_SIZE 12
#define MAC_SIZE 16
#define ENCRYPTED_MESSAGE_OFFSET ( IV_SIZE + MAC_SIZE )

char *p_secret = NULL;

sgx_status_t enclave_ra_init(sgx_ec256_public_t *p_gb, size_t len, sgx_ra_context_t *p_ra_context_out)
{
    sgx_status_t ret = SGX_SUCCESS;

    int retries = 500;
    while ( ( ret = sgx_ra_init( p_gb, 0, p_ra_context_out ) ) != SGX_SUCCESS && retries-- ) continue;

    return ret;
}

sgx_status_t enclave_process_encrypted_secret( char *p_encrypted_secret, size_t secret_len, sgx_ra_context_t *p_ra_context, size_t context_len )
{
    sgx_status_t ret = SGX_SUCCESS;

    sgx_ra_key_128_t *p_sk_key = ( sgx_ra_key_128_t * ) malloc( sizeof( sgx_ra_key_128_t ) );
    memset( p_sk_key, 0, sizeof( sgx_ra_key_128_t ) );
    ret = sgx_ra_get_keys( *p_ra_context, SGX_RA_KEY_SK, p_sk_key );
    if ( SGX_SUCCESS != ret )
    {
        emit_debug( "Unable to get SK key!" );
        return SGX_ERROR_INVALID_PARAMETER;
    }

    emit_debug( "SK key:" );
    print_byte_array( p_sk_key, sizeof( sgx_ec_key_128bit_t ) );

    uint32_t decrypted_secret_len = secret_len - IV_SIZE - MAC_SIZE;
    char *p_decrypted_secret = ( char * ) calloc( decrypted_secret_len + 1, 1 );
    
    if ( ( ret = sgx_rijndael128GCM_decrypt( p_sk_key,
                             ( uint8_t * ) p_encrypted_secret + ENCRYPTED_MESSAGE_OFFSET,
                                           secret_len - IV_SIZE - MAC_SIZE,
                             ( uint8_t * ) p_decrypted_secret,
                             ( uint8_t * ) p_encrypted_secret, IV_SIZE,
                                           NULL, 0,
                             ( sgx_aes_gcm_128bit_tag_t * ) ( ( ( uint8_t * ) p_encrypted_secret ) + IV_SIZE ) ) )
         != SGX_SUCCESS )
    {
        emit_debug( "Unable to decrypt message!" );
        return ret;
    }

    p_secret = p_decrypted_secret;

    return ret;
}

void enclave_emit_secret( )
{
    emit_debug( "Decrypted the following secret:" );
    emit_debug( p_secret );
}
