#include <restbed>
#include "keys.h"
#include "message.h"
#include "json-cpp.hpp"
#include "print_utils.h"
#include "base64_utils.h"
#include <curl/curl.h>
#include <chrono>
#include <thread>

#include "sgx_urts.h"
#include "enclave_u.h"
#include "sgx_ukey_exchange.h"

#define ENCLAVE_PATH "enclave.signed.so"
#define CERT_PATH "clientconc.pem"

#ifndef DEMO_VARIABLE
#define DEMO_VARIABLE 1
#endif

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

#define SPID_SIZE 16
#define QUOTE_BODY_SIZE 432
#define REQUEST_ID_MAX_LEN 1024
#define SECRET_MAX_LEN 2048
#define AES_GCM_IV_SIZE 12
#define MAC_SIZE 16
#define ENCRYPTED_SECRET_MAX_LEN ( SECRET_MAX_LEN + AES_GCM_IV_SIZE + MAC_SIZE )
#define _T(x) x

using namespace std;
using namespace restbed;
using std::chrono::seconds;

sgx_enclave_id_t eid;

uint8_t smart_meter_spid[SPID_SIZE] = {
    0xCB, 0x83, 0x1C, 0xE1,
    0x94, 0xA3, 0x73, 0x33,
    0x69, 0x57, 0x5A, 0xE6,
    0xE6, 0xE9, 0xDB, 0xEE
};

bool started_remote_attestation = false;
bool completed_remote_attestation = false;
bool sent_secret = false;

FILE* OUTPUT = stdout;
Service service;

/* Function declarations*/
sgx_status_t handle_request_secret_data( remote_attestation_message_t *p_ra_response_message );
sgx_status_t handle_msg1( remote_attestation_message_t *p_ra_message, remote_attestation_message_t *p_ra_response_message );
sgx_status_t handle_msg3( remote_attestation_message_t *p_ra_message, remote_attestation_message_t *p_ra_response_message );

/* OCALLs */
void emit_debug(const char *buf)
{
  printf("\n%s\n", buf);
}

void print_byte_array(void *mem, size_t len)
{
    int i, count=0;
    uint8_t *array = (uint8_t *) mem;
    for (i=0; i<len; i++)
    {   
        if (count == 0) printf("\n");
        count = (count + 1) % 8;
        printf("0x%x", array[i]);
        if (i+1 < len) printf(", ");
    }   
    printf("\n");
}

/* Helper functions */
void decode_ra_message_payload( remote_attestation_message_t *p_ra_message, uint8_t **pp_decoded_payload, size_t *p_decoded_size)
{
    size_t encoded_size = p_ra_message->payload.size();
    char *encoded_payload = (char *) malloc(encoded_size);
    memset(encoded_payload, 0, encoded_size);
    memcpy(encoded_payload, p_ra_message->payload.c_str(), encoded_size);

    size_t decoded_size = encoded_size;
    uint8_t *decoded_payload = (uint8_t *) malloc(decoded_size);
    memset(decoded_payload, 0, decoded_size);

    base64decode(encoded_payload, encoded_size, decoded_payload, &decoded_size);

    *pp_decoded_payload = decoded_payload;
    *p_decoded_size = decoded_size;

    SAFE_FREE( encoded_payload );
}

void generate_ra_response_message( int message_type, void *p_payload, size_t payload_size, remote_attestation_message_t *p_ra_request_message)
{
    size_t encoded_payload_size = payload_size * 2;
    char *encoded_payload = (char *) malloc(encoded_payload_size);
    memset(encoded_payload, 0, encoded_payload_size);

    base64encode(p_payload, payload_size, encoded_payload, encoded_payload_size);
    std::string encoded_payload_str(encoded_payload);

    remote_attestation_message_t ra_response_message{ message_type, encoded_payload_str };

    *p_ra_request_message = ra_response_message;

    SAFE_FREE(encoded_payload);
}

void generate_challenge_msg( remote_attestation_message_t *p_ra_challenge, sgx_ec256_public_t *p_g_b )
{
    generate_ra_response_message( CHALLENGE, p_g_b, sizeof(sgx_ec256_public_t), p_ra_challenge );
}

void generate_secret_msg( remote_attestation_message_t *p_encrypted_secret, char *p_secret, size_t secret_size )
{
    generate_ra_response_message( SECRET, p_secret, secret_size, p_encrypted_secret );
}

sgx_status_t handle_request_secret_data( remote_attestation_message_t *p_ra_response_message )
{
    sgx_status_t ret = SGX_SUCCESS, status = SGX_SUCCESS;

    if ( !started_remote_attestation )
    {
#ifdef DEMO_VARIABLE
        fprintf( OUTPUT, "\nReceived a secret request, but the client has not been attested yet.\nStarting remote attestation process. Press [ RETURN ] to continue..\n" );
        getchar( );
#endif
        sgx_ec256_public_t g_b;
        memset( &g_b, 0, sizeof( sgx_ec256_public_t ) );
#ifdef DEMO_VARIABLE
        fprintf( OUTPUT, "\nGenerating a key pair to be used in the remote attestation process.. " );
#endif
        ret = enclave_ra_init( eid, &status, &g_b );
        if ( SGX_SUCCESS != ret || SGX_SUCCESS != status )
        {
#ifdef DEMO_VARIABLE
            fprintf( OUTPUT, "[ FAIL ]\n" );
#endif
            fprintf( OUTPUT, "\nError: couldn't initialize RA process!\n" );
            return status;
        }
#ifdef DEMO_VARIABLE
        fprintf( OUTPUT, "[ OK ]\n" );
#endif
#ifdef DEBUG_VARIABLE
        fprintf( OUTPUT, "\nSuccessfully generated key pair to be used in the remote attestation process..\n" );
#endif
#ifdef DEBUG_VARIABLE
        fprintf( OUTPUT, "\ng_b\n" );
        print_byte_array( &g_b, sizeof( sgx_ec256_public_t ) );
#endif
#ifdef DEMO_VARIABLE
        fprintf( OUTPUT, "\nGenerating Challenge and sending as response.. [ OK ]\n" );
#endif
        generate_challenge_msg( p_ra_response_message, &g_b );

        started_remote_attestation = true;
        return status;
    }
    else if ( !completed_remote_attestation )
    {
        fprintf( OUTPUT, "\nReceived a secret request, but the attestation process has not been completed yet. Please check if the client has implemented the correct protocol.\n" );
        return SGX_ERROR_UNEXPECTED;
    }
    else
    {
#ifdef DEMO_VARIABLE
        fprintf( OUTPUT, "\nReceived a secret request from an attested client.\n" );
#endif
        char secret[ SECRET_MAX_LEN ] = { 0 };
        char encrypted_secret[ ENCRYPTED_SECRET_MAX_LEN ] = { 0 };
        fprintf( OUTPUT, "\nPlease enter a secret message to be securely sent to the Client enclave:\n" );
        fgets( secret, SECRET_MAX_LEN, stdin );
        if ( ( strlen( secret ) > 0 ) && ( secret[ strlen( secret ) - 1 ] == '\n' ) )
            secret[ strlen( secret ) - 1 ] = '\0';
#ifdef DEMO_VARIABLE 
        fprintf( OUTPUT, "\nEncrypting secret.. " );
#endif
        ret = enclave_encrypt( eid, &status, ( uint8_t * ) secret, SECRET_MAX_LEN, ( ( uint8_t * ) encrypted_secret ) , ENCRYPTED_SECRET_MAX_LEN );
        if ( SGX_SUCCESS != status )
        {
#ifdef DEMO_VARIABLE 
            fprintf( OUTPUT, "[ FAIL ]\n" );
            return status;
#endif
        }
#ifdef DEMO_VARIABLE 
        fprintf( OUTPUT, "[ OK ]\n" );
        fprintf( OUTPUT, "\nReal secret:\n%s\n", secret );
        fprintf( OUTPUT, "\nEncrypted secret:\n%s\n", encrypted_secret );
#endif
#ifdef DEMO_VARIABLE 
        fprintf( OUTPUT, "\nGenerating response with encrypted secret and sending to Client.. [ OK ]\n" );
#endif
        generate_secret_msg( p_ra_response_message, encrypted_secret, ENCRYPTED_SECRET_MAX_LEN );
        sent_secret = true;

        return status;
    }
}

size_t ias_response_header_parser( void *ptr, size_t size,
                       size_t nmemb, void *userdata )
{
    int parsed_fields = 0, response_status, content_length, ret = size * nmemb;
    
    char *x = ( char * ) calloc( size + 1, nmemb );
    assert( x );
    memcpy( x, ptr, size * nmemb );
    parsed_fields = sscanf( x, "HTTP/1.1 %d", &response_status );
    if ( parsed_fields == 1 )
    {
        ( ( ias_response_header_t * ) userdata )->response_status = response_status;
        return ret;
    }

    parsed_fields = sscanf( x, "content-length: %d", &content_length );
    if ( parsed_fields == 1 ) 
    {   
        ( ( ias_response_header_t * ) userdata )->content_length = content_length;
        return ret;
    }

    char *p_request_id = ( char * ) calloc( 1, REQUEST_ID_MAX_LEN );
    parsed_fields = sscanf( x, "request-id: %s", p_request_id );
    if ( parsed_fields == 1 )
    {
        std::string request_id_str( p_request_id );
        ( ( ias_response_header_t * ) userdata )->request_id = request_id_str;
        return ret;
    }
    return ret;
}

size_t ias_reponse_body_handler( void *ptr, size_t size,
                       size_t nmemb, void *userdata )
{
    size_t realsize = size * nmemb;
    ias_response_container_t *ias_response_container = ( ias_response_container_t * ) userdata;
    ias_response_container->p_response = ( char * ) realloc( ias_response_container->p_response, ias_response_container->size + realsize + 1 );
    if ( ias_response_container->p_response == NULL )
    {
        fprintf( OUTPUT, "\nUnable to allocate extra memory\n" );
        return 0;
    }

    memcpy( &( ias_response_container->p_response[ ias_response_container->size ] ), ptr, realsize );
    ias_response_container->size += realsize;
    ias_response_container->p_response[ ias_response_container->size ] = 0;

    return realsize;
}

sgx_status_t retrieve_sig_rl_from_IAS( uint8_t **pp_sig_rl, uint32_t *p_sig_rl_size, sgx_epid_group_id_t gid )
{
    sgx_status_t ret = SGX_SUCCESS;

    ias_response_header_t response_header;
    ias_response_container_t ias_response_container;
    ias_response_container.p_response = ( char * ) malloc( 1 );
    ias_response_container.size = 0;

    CURL *curl;
    CURLcode res;

    static const char *p_cert_file = CERT_PATH;

    curl_global_init( CURL_GLOBAL_DEFAULT );

    curl = curl_easy_init( );
    if ( !curl )
    {
        fprintf( OUTPUT, "\nError when creating a curl handler [%s].\n",
                 __FUNCTION__ );
        return SGX_ERROR_UNEXPECTED;
    }
    char url[90];
    sprintf( url, "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v1/sigrl/%02x%02x%02x%02x", gid[3], gid[2], gid[1], gid[0] ); // Converting GID endianness
    curl_easy_setopt( curl, CURLOPT_URL, url );
#ifdef DEBUG_VARIABLE
    curl_easy_setopt( curl, CURLOPT_VERBOSE, 1L );
#endif
    curl_easy_setopt( curl, CURLOPT_SSLCERTTYPE, "PEM" );
    curl_easy_setopt( curl, CURLOPT_SSLCERT, p_cert_file );
    curl_easy_setopt( curl, CURLOPT_HEADERFUNCTION, ias_response_header_parser );
    curl_easy_setopt( curl, CURLOPT_HEADERDATA, &response_header );
    curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, ias_reponse_body_handler );
    curl_easy_setopt( curl, CURLOPT_WRITEDATA, &ias_response_container );
    curl_easy_setopt( curl, CURLOPT_NOPROGRESS, 1L);

    res = curl_easy_perform( curl );
    if ( res != CURLE_OK )
    {
        fprintf( stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror( res ) );
    }

    if ( response_header.content_length != ias_response_container.size )
    {
        fprintf( OUTPUT, "\nBody size differs from the one specified in the header [ %u %lu ]!\n", response_header.content_length, ias_response_container.size );
        ret = SGX_ERROR_UNEXPECTED;
    }

    size_t encoded_size = response_header.content_length;
    size_t sig_rl_size = encoded_size;
    uint8_t *p_sig_rl = ( uint8_t * ) malloc( sig_rl_size );
    memset( p_sig_rl, 0, sig_rl_size );

    if ( encoded_size > 0 ) base64decode( ias_response_container.p_response, encoded_size, p_sig_rl, &sig_rl_size );

    *pp_sig_rl = p_sig_rl;
    *p_sig_rl_size = sig_rl_size;

    curl_easy_cleanup( curl );
    curl_global_cleanup( );

    return ret;
}

bool verify_quote_with_IAS( char *p_encoded_quote, attestation_verification_report_t *p_avr )
{
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nVerifying quote with IAS.. " );
#endif
    CURL *curl;
    CURLcode res;

    curl_global_init( CURL_GLOBAL_DEFAULT );

    curl = curl_easy_init( );
    if ( !curl )
    {
        fprintf( OUTPUT, "\nError when creating a curl handler [%s].\n",
                 __FUNCTION__ );
        return SGX_ERROR_UNEXPECTED;
    }

    // Request variables
    const char *url = "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v1/report";
    static const char *p_cert_file = CERT_PATH;
    std::string isv_enclave_quote( p_encoded_quote );
    attestation_evidence_payload_t aep{ isv_enclave_quote };
    const auto aep_json = jsoncpp::to_string( aep );

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    // Request setopt
    curl_easy_setopt( curl, CURLOPT_URL, url );
#ifdef DEBUG_VARIABLE
    curl_easy_setopt( curl, CURLOPT_VERBOSE, 1L );
#endif
    curl_easy_setopt( curl, CURLOPT_SSLCERTTYPE, "PEM" );
    curl_easy_setopt( curl, CURLOPT_SSLCERT, p_cert_file );
    curl_easy_setopt( curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt( curl, CURLOPT_HTTPHEADER, headers );
    curl_easy_setopt( curl, CURLOPT_POSTFIELDS, aep_json.c_str( ) );

    // Response variables
    ias_response_header_t response_header;

    ias_response_container_t ias_response_container;
    ias_response_container.p_response = ( char * ) malloc( 1 );
    ias_response_container.size = 0;

    // Response setopt
    curl_easy_setopt( curl, CURLOPT_HEADERFUNCTION, ias_response_header_parser );
    curl_easy_setopt( curl, CURLOPT_HEADERDATA, &response_header );
    curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, ias_reponse_body_handler );
    curl_easy_setopt( curl, CURLOPT_WRITEDATA, &ias_response_container );

    res = curl_easy_perform( curl );
    if ( res != CURLE_OK )
    {
        fprintf( stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror( res ) );
                return false;
    }
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nResponse from IAS:\n%s\n", ias_response_container.p_response );
#endif
    // Build attestation verification report from response JSON
    attestation_verification_report_t avr;
    std::string avr_str( ias_response_container.p_response );
    jsoncpp::parse( avr, avr_str );
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nVerifying isvEnclaveQuoteStatus.. " );
#endif    
    if ( avr.isv_enclave_quote_status.compare( "OK" ) != 0 )
    {
#ifdef DEMO_VARIABLE
        fprintf( OUTPUT, "[ FAIL ]\n" );
#endif
        fprintf( OUTPUT, "\nQuote has not been verified by IAS!\n" );
        return false;
    }
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "[ OK ]\n" );
#endif
#ifdef DEBUG_VARIABLE
    fprintf( OUTPUT, "\nSuccessfully verified Quote with IAS\n" );
#endif
    p_avr->report_id = avr.report_id;
    p_avr->isv_enclave_quote_status = avr.isv_enclave_quote_status;
    p_avr->timestamp = avr.timestamp;

    return true;
}

void generate_msg2( remote_attestation_message_t *p_ra_msg2, sgx_ra_msg2_t *p_msg2, uint32_t msg2_size )
{
#ifdef DEBUG_VARIABLE
    fprintf( OUTPUT, "\ng_b:\n" );
    print_byte_array( &p_msg2->g_b, sizeof( sgx_ec256_public_t ) );
    fprintf( OUTPUT, "\nSPID:\n" );
    print_byte_array( &p_msg2->spid, sizeof( sgx_spid_t ) );
    fprintf( OUTPUT, "\nquote_type:\n" );
    print_byte_array( &p_msg2->quote_type, sizeof( uint16_t ) );
    fprintf( OUTPUT, "\nkdf_id:\n" );
    print_byte_array( &p_msg2->kdf_id, sizeof( uint16_t ) );
    fprintf( OUTPUT, "\nsign_gb_ga:\n" );
    print_byte_array( &p_msg2->sign_gb_ga, sizeof( sgx_ec256_signature_t ) );
    fprintf( OUTPUT, "\nmac:\n" );
    print_byte_array( &p_msg2->mac, sizeof( sgx_mac_t ) );
    fprintf( OUTPUT, "\nsig_rl_size:\n");
    print_byte_array( &p_msg2->sig_rl_size, sizeof( uint32_t ) );
    fprintf( OUTPUT, "\nsig_rl:\n" );
    print_byte_array( &p_msg2->sig_rl, p_msg2->sig_rl_size );
#endif
    generate_ra_response_message( MSG2, p_msg2, msg2_size, p_ra_msg2 );
}

void generate_ra_result_msg( remote_attestation_message_t *p_ra_result_msg, uint8_t *p_result, size_t result_len )
{
    generate_ra_response_message( REMOTE_ATTESTATION_RESULT, p_result, result_len, p_ra_result_msg );
}

sgx_status_t process_msg1( sgx_ra_msg1_t *p_msg1, sgx_ra_msg2_t **pp_msg2_out, uint32_t *p_msg2_size )
{
    sgx_status_t ret = SGX_SUCCESS, status = SGX_SUCCESS;

    ret = enclave_set_ga( eid, &p_msg1->g_a, sizeof( sgx_ec256_public_t ) );
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nDeriving shared keys.. " );
#endif
    ret = enclave_derive_keys( eid, &status );
    if ( SGX_SUCCESS != ret )
    {
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "[ FAIL ]\n" );
#endif        
        fprintf( OUTPUT, "\nError when deriving keys!\n" );
        print_error_message( ret );
    }
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "[ OK ]\n" );
#endif
#ifdef DEBUG_VARIABLE
    printf("\nSuccessfully derived all keys\n");
#endif
    uint8_t* sig_rl = NULL;
    uint32_t sig_rl_size = 0;
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nRetrieving SigRL from IAS.. " );
#endif
    ret = retrieve_sig_rl_from_IAS( &sig_rl, &sig_rl_size, p_msg1->gid );
    if ( SGX_SUCCESS != ret )
    {
#ifdef DEMO_VARIABLE
        fprintf( OUTPUT, "[ FAIL ]\n" );
#endif
        fprintf( OUTPUT, "\nSomething went wrong while retrieving SigRL from IAS!\n" );
        return ret;
    }
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "[ OK ]\n" );
#endif
    uint32_t msg2_size = sizeof( sgx_ra_msg2_t ) + sig_rl_size;
    *p_msg2_size = msg2_size;
#ifdef DEBUG_VARIABLE
    fprintf( OUTPUT, "\nMSG2 size: %d\n", msg2_size );
#endif
    sgx_ra_msg2_t *p_msg2 = ( sgx_ra_msg2_t * ) malloc( msg2_size );
    memset( p_msg2, 0, msg2_size );

    // g_b
    ret = enclave_get_gb( eid, &status, &p_msg2->g_b );
    if ( SGX_SUCCESS != status || SGX_SUCCESS != ret )
    {
        fprintf( OUTPUT, "\nUnable to retrieve g_b from enclave!\n" );
        print_error_message( status );
        return status;
    }

    // SPID
    memcpy( &p_msg2->spid.id, &smart_meter_spid, SPID_SIZE );
#ifdef DEBUG_VARIABLE
    printf("\nSuccessfully copied SPID\n");
#endif
    // Quote type
    p_msg2->quote_type = SGX_UNLINKABLE_SIGNATURE;
#ifdef DEBUG_VARIABLE
    printf("\nSuccessfully copied quote_type\n");
#endif
    // kdf_id
    p_msg2->kdf_id = 0x0001;
#ifdef DEBUG_VARIABLE
    printf("\nSuccessfully copied kdf_id\n");
#endif
    // sign_gb_ga
    ret = enclave_get_sign_gb_ga( eid, &status, &p_msg2->sign_gb_ga );
    if ( SGX_SUCCESS != ret || SGX_SUCCESS != status ) {
        fprintf( OUTPUT, "\nUnable to retrieve sign_gb_ga from enclave!\n" );
        return status;
    }
#ifdef DEBUG_VARIABLE
    printf( "\nSuccessfully generated sign_gb_ga\n" );
#endif
    // MAC
    uint32_t plain_text_size = sizeof( sgx_ec256_public_t )     // g_b
                             + sizeof( sgx_spid_t )             // SPID
                             + sizeof( uint16_t )               // quote_type
                             + sizeof( uint16_t )               // kdf_id
                             + sizeof( sgx_ec256_signature_t ); // sign_gb_ga

    ret = enclave_compute_msg2_mac( eid, &status,
                               ( uint8_t * ) p_msg2,
                               plain_text_size,
                               &p_msg2->mac );

    if ( SGX_SUCCESS != ret || SGX_SUCCESS != status ) return ret;
#ifdef DEBUG_VARIABLE
    printf("\nSuccessfully generated MAC\n");
#endif
    // sig_rl_size
    p_msg2->sig_rl_size = sig_rl_size;
#ifdef DEBUG_VARIABLE
    printf("\nSuccessfully copied sig_rl_size\n");
#endif
    // sig_rl
    memcpy(&p_msg2->sig_rl[0], sig_rl, sig_rl_size);
#ifdef DEBUG_VARIABLE
    printf("\nSuccessfully copied sig_rl\n");
#endif
    *pp_msg2_out = p_msg2;
#ifdef DEBUG_VARIABLE
    printf("\nSuccessfully copied MSG2\n");
#endif
    return ret;
}

sgx_status_t handle_msg1( remote_attestation_message_t *p_ra_message, remote_attestation_message_t *p_ra_response_message )
{
    sgx_status_t ret = SGX_SUCCESS;

#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nReceived Msg1 from Client..\n" );
#endif
    size_t decoded_size;
    uint8_t *p_decoded_payload = NULL;
    decode_ra_message_payload( p_ra_message, &p_decoded_payload, &decoded_size );

    sgx_ra_msg1_t msg1;
    memcpy( &msg1, p_decoded_payload, decoded_size );
#ifdef DEBUG_VARIABLE
    fprintf( OUTPUT, "g_a:" );
    print_byte_array( &msg1.g_a, sizeof( sgx_ec256_public_t ) );
    fprintf( OUTPUT, "gid:" );
    print_byte_array( &msg1.gid, sizeof( sgx_epid_group_id_t ) );
#endif

#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nProcessing Msg1..\n" );
#endif
    sgx_ra_msg2_t *p_msg2 = NULL;
    uint32_t msg2_size;
    process_msg1( &msg1, &p_msg2, &msg2_size );
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nGenerating Msg2.. [ OK ]\n" );
#endif
    generate_msg2( p_ra_response_message, p_msg2, msg2_size );
    SAFE_FREE( p_decoded_payload );
    return ret;
}

sgx_status_t handle_msg3( remote_attestation_message_t *p_ra_message, remote_attestation_message_t *p_ra_response_message )
{
    sgx_status_t ret = SGX_SUCCESS;
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nReceived Msg3 from Client..\n" );
#endif
    size_t decoded_size;
    uint8_t *p_decoded_payload = NULL;
    decode_ra_message_payload( p_ra_message, &p_decoded_payload, &decoded_size );

    sgx_ra_msg3_t *p_msg3 = ( sgx_ra_msg3_t * ) malloc( decoded_size );
    memcpy( p_msg3, p_decoded_payload, decoded_size );
    SAFE_FREE( p_decoded_payload );

    uint32_t sig_len = *( ( uint32_t * ) ( ( ( uint8_t * ) &p_msg3->quote ) + QUOTE_BODY_SIZE ) );
    uint32_t quote_size = QUOTE_BODY_SIZE + sizeof( uint32_t ) + sig_len;
#ifdef PRINT_MRENCLAVE
    sgx_quote_t *p_quote = ( sgx_quote_t * ) malloc( quote_size );
    memcpy( p_quote, &p_msg3->quote, quote_size );
    fprintf( OUTPUT, "\nMRENCLAVE:\n" );
    print_byte_array( &p_quote->report_body.mr_enclave, sizeof( sgx_measurement_t ) );
    sgx_report_body_t *p_report_body = ( sgx_report_body_t * ) malloc( sizeof( sgx_report_body_t ) );
    SAFE_FREE( p_quote );
#endif
    uint32_t encoded_quote_size = 2 * quote_size;

    char *p_encoded_quote = ( char* ) malloc(encoded_quote_size);
    int ret2;
    ret2 = base64encode( &p_msg3->quote, quote_size, p_encoded_quote, encoded_quote_size );
    if ( SGX_SUCCESS != ret2 )
    {
        fprintf( OUTPUT, "\nError, call base64encode [%s].",
                __FUNCTION__ );
        SAFE_FREE( p_msg3 );
        SAFE_FREE( p_encoded_quote );
        return ret;
    }
#ifdef DEBUG_VARIABLE
    fprintf(OUTPUT, "\nCall base64encode success.\n");
    fprintf(OUTPUT, "Encoded quote: \n%s\n", p_encoded_quote);
#endif
    bool ra_result = true;
    attestation_verification_report_t avr;

    ra_result = verify_quote_with_IAS( p_encoded_quote, &avr );
    if ( ra_result ) completed_remote_attestation = true;
    else started_remote_attestation = false;
    const auto avr_json_str = jsoncpp::to_string( avr );
#ifdef DEMO_VARIABLE
    fprintf(OUTPUT, "\nForwarding IAS response to Client.\n");
#endif
    generate_ra_result_msg( p_ra_response_message, ( uint8_t * ) avr_json_str.c_str( ), avr_json_str.size( ) );
    SAFE_FREE( p_encoded_quote );
    SAFE_FREE( p_msg3 );
    return ret;
}

/* Restbed request handlers */
// For simplification reasons, every request will be required to be in json format and made to one single endpoint
void post_method_handler( const shared_ptr< Session > session )
{
    const auto request = session->get_request( );

    if ( request->get_header( "Content-Type", String::lowercase ) == "application/json" )
    {
        if ( request->has_header( "Content-Length" ) )
        {
            int length = request->get_header( "Content-Length", 0 );
            session->fetch( length, [ ]( const shared_ptr< Session > session, const Bytes& )
            {
                sgx_status_t ret = SGX_ERROR_INVALID_PARAMETER;
                const auto request = session->get_request( );
                const auto body = request->get_body( );

                remote_attestation_message_t ra_message, ra_response_message;

                std::string str_body( body.begin( ), body.end( ) );
                jsoncpp::parse( ra_message, str_body );

                if ( REQUEST_SECRET_DATA == ra_message.message_type)
                {
#ifdef DEBUG_VARIABLE
                    fprintf( OUTPUT, "\nReceived REQUEST_SECRET_DATA!\n" );
#endif
                    ret = handle_request_secret_data( &ra_response_message );
                }
                else if ( MSG1 == ra_message.message_type )
                {
                    ret = handle_msg1( &ra_message, &ra_response_message );
                }
                else if ( MSG3 == ra_message.message_type )
                {
#ifdef DEBUG_VARIABLE
                    fprintf( OUTPUT, "\nReceived MSG3!\n" );
#endif
                    ret = handle_msg3( &ra_message, &ra_response_message );
                }

                if ( SGX_SUCCESS != ret ) session->close( BAD_REQUEST );

                const auto response_body = jsoncpp::to_string( ra_response_message );
                size_t response_body_len = response_body.size( );

                session->set_header( "Accept", "application/json" );
                session->set_header( "Host", "http://localhost" );
                session->set_header( "Content-Type", "application/json" );
                session->set_header( "Content-Length", std::to_string( response_body_len ) );

                session->close( OK, response_body );
                if ( sent_secret )
                {
                    std::this_thread::sleep_for( seconds( 1 ) );
                    service.stop( );
                }
            } );
        }
        else
        {
            session->close( BAD_REQUEST );
        }
    }
    else
    {
        session->close( BAD_REQUEST );
    }
}

/* main */
int main()
{
    sgx_status_t ret = SGX_SUCCESS, status = SGX_SUCCESS;
    int updated = 0;
    sgx_launch_token_t launch_token;

/*  #######################################################
    #                  Enclave creation                   #
*///#######################################################

    memset(&launch_token, 0, sizeof(sgx_launch_token_t));
#ifdef DEMO_VARIABLE
//    fprintf( OUTPUT, "\nCreating SP enclave.. " );
#endif
    ret = sgx_create_enclave(_T(ENCLAVE_PATH),
                             SGX_DEBUG_FLAG,
                             &launch_token,
                             &updated,
                             &eid, NULL);
    if (ret != SGX_SUCCESS)
    {
#ifdef DEMO_VARIABLE
//        fprintf( OUTPUT, "[ FAIL ]\n" );
#endif
        fprintf(OUTPUT, "\nError, call sgx_create_enclave fail [%s].",
                __FUNCTION__);
        return -1;
    }
#ifdef DEMO_VARIABLE
//    fprintf( OUTPUT, "[ OK ]\n" );
#endif
#ifdef DEBUG_VARIABLE
    fprintf(OUTPUT, "\nCall sgx_create_enclave success.\n");
#endif
/*  #######################################################
    #                 REST server                 #
*///#######################################################

    auto resource = make_shared< Resource >();
    resource->set_path("/remote-attestation");
    resource->set_method_handler("POST", { { "Accept", "application/json" }, { "Content-Type", "application/json" } }, &post_method_handler );

    auto settings = make_shared< Settings >( );
    // Read port as a program parameter
    settings->set_port( 8888 );
    settings->set_default_header( "Connection", "close" );
    settings->set_connection_timeout( seconds( 500 ) );

#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "SP started to listen at http://localhost:8888/remote-attestation..\n" );
#endif
    service.publish( resource );
    service.start( settings );
#ifdef DEBUG_VARIABLE
    printf("\nStarted serving at port 8888\n");
#endif
/*  #######################################################
    #                    Cleaning up                      #
*///#######################################################

    sgx_destroy_enclave(eid);

    printf("\nEnter a character before exit ...\n");
    getchar();

    return ret;
}
