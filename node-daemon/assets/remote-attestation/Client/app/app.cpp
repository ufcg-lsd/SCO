#include <stdio.h>
#include <string>
#include <memory>
#include <restbed>
#include "message.h"
#include "json-cpp.hpp"
#include "print_utils.h"
#include "base64_utils.h"
#include "string.h"
#include <chrono>

#include "sgx_urts.h"
#include "enclave_u.h"
#include "sgx_ukey_exchange.h"

#define ENCLAVE_PATH "enclave.signed.so"
#define SECRET_MAX_LEN 2048
#define AES_GCM_IV_SIZE 12
#define MAC_SIZE 16
#define ENCRYPTED_SECRET_MAX_LEN ( SECRET_MAX_LEN + AES_GCM_IV_SIZE + MAC_SIZE )

#ifndef DEMO_VARIABLE
#define DEMO_VARIABLE 1
#endif

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

#define _T(x) x
#define QUOTE_BODY_SIZE 436

using namespace std;
using namespace restbed;
using namespace std::chrono;

sgx_enclave_id_t eid;

FILE* OUTPUT = stdout;
bool completed_attestation_process = false;

/* OCALLs */
void print_byte_array( void *mem, size_t len )
{
    int i, count=0;
    uint8_t *array = ( uint8_t * ) mem;
    for ( i=0; i<len; i++ )
    {   
        if ( count == 0 ) printf( "\n" );
        count = ( count + 1 ) % 8;
        printf( "0x%x", array[i] );
        if ( i+1 < len ) printf( ", " );
    }   
    printf( "\n" );

}

void emit_debug( const char *dbg_message )
{
    printf( "\nEnclave: %s\n", dbg_message );
}

/* Misc debugging functions */
void debug_print_gb( sgx_ec256_public_t *p_gb )
{
    fprintf( OUTPUT, "\ng_b:\n" );
    print_byte_array( p_gb, sizeof( sgx_ec256_public_t ) );
}

void debug_print_msg1( sgx_ra_msg1_t *p_msg1 )
{
    fprintf( OUTPUT, "\ng_a:\n" );
    print_byte_array( &p_msg1->g_a, sizeof( sgx_ec256_public_t ) );
    fprintf( OUTPUT, "\ngid:\n" );
    print_byte_array( &p_msg1->gid, sizeof( sgx_epid_group_id_t ) );
}

void debug_print_msg2( sgx_ra_msg2_t *p_msg2 )
{
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
    fprintf( OUTPUT, "\nsig_rl_size:\n" );
    print_byte_array( &p_msg2->sig_rl_size, sizeof( uint32_t ) );
    fprintf( OUTPUT, "\nsig_rl:\n" );
    print_byte_array( &p_msg2->sig_rl, p_msg2->sig_rl_size );
}

void debug_print_msg3( sgx_ra_msg3_t *p_msg3, uint32_t msg3_size )
{
    fprintf( OUTPUT, "\nMSG3 size: %d\n", msg3_size );

    uint32_t sig_len = *( ( uint32_t * ) ( ( ( uint8_t * ) &p_msg3->quote ) + 432 ) );
    fprintf( OUTPUT, "\nsig_len: %d\n", sig_len );

    uint32_t quote_size = QUOTE_BODY_SIZE + sig_len;
    fprintf( OUTPUT, "\nquote_size: %d\n", quote_size );

    double encoded_quote_size = quote_size * 2;

    char *encoded_quote = ( char* ) malloc( encoded_quote_size );
    base64encode( &p_msg3->quote, quote_size, encoded_quote, encoded_quote_size );
    fprintf( OUTPUT, "Encoded quote: \n%s", encoded_quote );

    SAFE_FREE( encoded_quote );
}

/* Helper functions */
void generate_ra_request_message( int message_type, void *p_payload, size_t payload_size, remote_attestation_message_t *p_ra_request_message )
{
    size_t encoded_payload_size = payload_size * 2;
    char *encoded_payload = ( char * ) malloc( encoded_payload_size );
    memset( encoded_payload, 0, encoded_payload_size );

    base64encode( p_payload, payload_size, encoded_payload, encoded_payload_size );
    std::string encoded_payload_str( encoded_payload );

    remote_attestation_message_t ra_response_message{ message_type, encoded_payload_str };

    *p_ra_request_message = ra_response_message;

    SAFE_FREE( encoded_payload );
}

void generate_req_secret_msg_request( remote_attestation_message_t *p_ra_req_secret_msg_request )
{
    std::string empty_str("");
    remote_attestation_message_t ra_msg_tmp { REQUEST_SECRET_DATA, empty_str };
    *p_ra_req_secret_msg_request = ra_msg_tmp;
}

void generate_msg1( remote_attestation_message_t *p_ra_msg1, sgx_ra_msg1_t *p_msg1 )
{
    generate_ra_request_message( MSG1, p_msg1, sizeof(sgx_ra_msg1_t), p_ra_msg1 );
}

void generate_msg3( remote_attestation_message_t *p_ra_msg3, sgx_ra_msg3_t *p_msg3, uint32_t msg3_size )
{
    generate_ra_request_message( MSG3, p_msg3, msg3_size, p_ra_msg3 );
}

sgx_status_t retrieve_message_from_response( const shared_ptr< Response >& response, remote_attestation_message_t *p_ra_msg )
{
    if ( response->get_status_code( ) != OK )
    {
        fprintf( OUTPUT, "\nResponse is not OK\n" );
        fprintf( OUTPUT, "\nResponse status: %d\n", response->get_status_code( ) );
    }
    else if ( response->get_header( "Content-Type", String::lowercase ) == "application/json" )
    {
        if ( response->has_header( "Content-Length" ) ) 
        {
            auto response_body_size = response->get_header( "Content-Length", 0 );
            Http::fetch( response_body_size, response );

            const auto response_body = response->get_body( );

            remote_attestation_message_t ra_challenge_msg;

            std::string response_body_str( response_body.begin( ), response_body.end( ) );
            jsoncpp::parse( ra_challenge_msg, response_body_str );

            *p_ra_msg = ra_challenge_msg;
            return SGX_SUCCESS;
        }
        else
        {
            printf("\nResponse has no size!\n");
            return SGX_ERROR_UNEXPECTED;
        }
    }
    else
    {
        printf("\nWrong Content-Type!\n");
        return SGX_ERROR_UNEXPECTED;
    }
}

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
}

sgx_status_t retrieve_challenge_from_response( const shared_ptr< Response >& response, sgx_ec256_public_t *p_g_b )
{
    sgx_status_t ret = SGX_SUCCESS;

    remote_attestation_message_t ra_challenge_msg;
    ret = retrieve_message_from_response( response, &ra_challenge_msg );
    if ( SGX_SUCCESS != ret ) return ret;

    if ( ra_challenge_msg.message_type != CHALLENGE ) return SGX_ERROR_UNEXPECTED;

    size_t decoded_payload_size;
    uint8_t *p_decoded_payload = NULL;

    decode_ra_message_payload( &ra_challenge_msg, &p_decoded_payload, &decoded_payload_size );

    memcpy( p_g_b, p_decoded_payload, sizeof( sgx_ec256_public_t ) );
    SAFE_FREE( p_decoded_payload );
    return SGX_SUCCESS;
}

sgx_status_t retrieve_msg2_from_response( const shared_ptr< Response >& response, sgx_ra_msg2_t **pp_msg2 )
{
    sgx_status_t ret = SGX_SUCCESS;

    remote_attestation_message_t ra_msg2;
    ret = retrieve_message_from_response( response, &ra_msg2 );
    if ( SGX_SUCCESS != ret ) return ret;

    if ( ra_msg2.message_type != MSG2 ) return SGX_ERROR_UNEXPECTED;

    size_t decoded_payload_size;
    uint8_t *p_decoded_payload = NULL;

    decode_ra_message_payload( &ra_msg2, &p_decoded_payload, &decoded_payload_size );
    sgx_ra_msg2_t *p_msg2 = ( sgx_ra_msg2_t * ) malloc( decoded_payload_size );
    memcpy( p_msg2, p_decoded_payload, decoded_payload_size );
    *pp_msg2 = p_msg2;
    SAFE_FREE( p_decoded_payload );
    return SGX_SUCCESS;
}

sgx_status_t retrieve_avr_from_response( const shared_ptr< Response >& response, attestation_verification_report_t *p_avr )
{
    sgx_status_t ret = SGX_SUCCESS;

    remote_attestation_message_t ra_avr_msg;
    ret = retrieve_message_from_response( response, &ra_avr_msg );
    if ( SGX_SUCCESS != ret ) return ret;

    if ( ra_avr_msg.message_type != REMOTE_ATTESTATION_RESULT ) return SGX_ERROR_UNEXPECTED;

    size_t decoded_payload_size;
    uint8_t *p_decoded_payload = NULL;

    decode_ra_message_payload( &ra_avr_msg, &p_decoded_payload, &decoded_payload_size );

    char *p_avr_json = ( char * ) calloc( decoded_payload_size + 1, 1 );
    memcpy( p_avr_json, p_decoded_payload, decoded_payload_size );
    std::string avr_json_str( p_avr_json );

    attestation_verification_report_t avr;
    jsoncpp::parse( avr, avr_json_str );

    p_avr->report_id = avr.report_id;
    p_avr->isv_enclave_quote_status = avr.isv_enclave_quote_status;
    p_avr->timestamp = avr.timestamp;

    SAFE_FREE( p_decoded_payload );
    SAFE_FREE( p_avr_json );

    return SGX_SUCCESS;
}

sgx_status_t retrieve_encrypted_secret_from_response( const shared_ptr< Response >& response, char **pp_encrypted_secret, size_t *p_secret_size )
{
    sgx_status_t ret = SGX_SUCCESS;

    remote_attestation_message_t secret_msg;
    ret = retrieve_message_from_response( response, &secret_msg );
    if ( SGX_SUCCESS != ret ) return ret;

    if ( secret_msg.message_type != SECRET )
    {
        fprintf( OUTPUT, "\nReceived wrong message type: %d\n", secret_msg.message_type );
        return SGX_ERROR_UNEXPECTED;
    }

    size_t decoded_payload_size;
    uint8_t *p_decoded_payload = NULL;

    decode_ra_message_payload( &secret_msg, &p_decoded_payload, &decoded_payload_size );

    char *p_encrypted_secret = ( char * ) calloc( decoded_payload_size, 1 );
    memcpy( p_encrypted_secret, p_decoded_payload, decoded_payload_size );

    *pp_encrypted_secret = p_encrypted_secret;
    *p_secret_size = decoded_payload_size;

    return SGX_SUCCESS;
}

/* main */
int main( )
{
    sgx_status_t ret = SGX_SUCCESS, status = SGX_SUCCESS;
    int updated = 0;
    sgx_launch_token_t launch_token;

    /* Enclave creation */
    memset( &launch_token, 0, sizeof( sgx_launch_token_t ) );
    ret = sgx_create_enclave( _T( ENCLAVE_PATH ),
                             SGX_DEBUG_FLAG,
                             &launch_token,
                             &updated,
                             &eid, NULL );
    if ( ret != SGX_SUCCESS )
    {
        fprintf( OUTPUT, "\nError, call sgx_create_enclave fail [%s].",
                __FUNCTION__ );
        return -1;
    }
#ifdef DEBUG_VARIABLE
    fprintf( OUTPUT, "\nCall sgx_create_enclave success.\n" );
#endif
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nCreated client enclave. Press [RETURN] to continue..\n" );
    getchar( );
#endif
    /* Requesting secrets */
    // TODO 5 define server and port as a program parameter
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nRequesting secret to SP at http://localhost:8888/remote-attestation\n" );
#endif
    auto settings = make_shared< Settings >( );
    settings->set_connection_timeout( seconds( 300 ) );

    auto req_secret_msg_request = make_shared< Request >( Uri( "http://localhost:8888/remote-attestation" ) );
    req_secret_msg_request->set_header( "Accept", "application/json" );
    req_secret_msg_request->set_header( "Host", "http://localhost" );
    req_secret_msg_request->set_header( "Content-type","application/json" );

    remote_attestation_message_t ra_req_secret_msg_request;
    generate_req_secret_msg_request( &ra_req_secret_msg_request );
    const auto req_secret_msg_request_body = jsoncpp::to_string( ra_req_secret_msg_request );

    size_t req_secret_msg_request_body_len = req_secret_msg_request_body.size( );

    req_secret_msg_request->set_method( "POST" );
    req_secret_msg_request->set_body( req_secret_msg_request_body );
    req_secret_msg_request->set_header( "Content-Length", std::to_string( req_secret_msg_request_body_len ) );

    /* Getting the response (Challenge) */
    auto req_secret_response = Http::sync( req_secret_msg_request, settings );
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nReceived a Challenge from SP. Starting Remote Attestation (RA) process. Press [RETURN] to continue..\n" );
    getchar( );
#endif
    sgx_ec256_public_t g_b;
    ret = retrieve_challenge_from_response( req_secret_response, &g_b );
    if ( SGX_SUCCESS != ret )
    {
        fprintf( OUTPUT, "\nReceived wrong message type!\n" );
        return -1;
    }
#ifdef DEBUG_VARIABLE
    debug_print_gb( &g_b );
#endif    
    /* Initialize Remote Attestation context on client side */
    sgx_ra_context_t ra_context;
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nCreating a RA context.. " );
#endif
    ret = enclave_ra_init( eid, &status, &g_b, sizeof( sgx_ec256_public_t ), &ra_context );    
#ifdef DEMO_VARIABLE
    if ( SGX_SUCCESS == ret ) fprintf( OUTPUT, "[ OK ]\n" );
#endif
    /* Generating MSG1 */
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nGenerating RA Msg1.. " );
#endif
    sgx_ra_msg1_t msg1;
    ret = sgx_ra_get_msg1( ra_context, eid, sgx_ra_get_ga, &msg1 );
    if ( SGX_SUCCESS != ret )
    {
#ifdef DEMO_VARIABLE
        fprintf( OUTPUT, "[ FAIL ]\n" );
#endif
        fprintf( OUTPUT, "\nUnable to get MSG1 from enclave\n" );
        return -1;
    }
#ifdef DEBUG_VARIABLE
    debug_print_msg1( &msg1 );
#endif
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "[ OK ]\n" );
#endif
    /* Sending MSG1 to SP */
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nReady to send Msg1 to SP. Press [RETURN] to continue..\n" );
    getchar( );
#endif
    auto msg1_request = make_shared< Request >( Uri( "http://localhost:8888/remote-attestation" ) );
    msg1_request->set_header( "Accept", "application/json" );
    msg1_request->set_header( "Host", "http://localhost" );
    msg1_request->set_header( "Content-type","application/json" );

    remote_attestation_message_t ra_msg1;
    generate_msg1( &ra_msg1, &msg1 );
    const auto ra_msg1_body = jsoncpp::to_string( ra_msg1 );

    size_t ra_msg1_body_len = ra_msg1_body.size( );

    msg1_request->set_method( "POST" );
    msg1_request->set_body( ra_msg1_body );
    msg1_request->set_header( "Content-Length", std::to_string( ra_msg1_body_len ) );

    /* Getting the response (MSG2) */
    auto msg1_response = Http::sync( msg1_request, settings );
    sgx_ra_msg2_t *p_msg2;
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nRetrieving Msg2 from response.. " );
#endif
    ret = retrieve_msg2_from_response( msg1_response, &p_msg2 );
    if ( SGX_SUCCESS != ret )
    {
#ifdef DEMO_VARIABLE
        fprintf( OUTPUT, "[ FAIL ]\n" );
#endif
        fprintf( OUTPUT, "\nReceived wrong message type!\n");
        SAFE_FREE( p_msg2 );
        sgx_destroy_enclave( eid );
        return -1;
    }
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "[ OK ]\n" );
#endif
#ifdef DEBUG_VARIABLE
    debug_print_msg2( p_msg2 );
#endif
    /* Generating MSG3 */
    uint32_t msg3_size;
    sgx_ra_msg3_t *p_msg3;
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nGenerating Msg3.. " );
#endif
    ret = sgx_ra_proc_msg2( ra_context,
                            eid,
                            sgx_ra_proc_msg2_trusted,
                            sgx_ra_get_msg3_trusted,
                            p_msg2,
                            sizeof( sgx_ra_msg2_t ),
                            &p_msg3,
                            &msg3_size
    );

    if ( SGX_SUCCESS != ret)
    {
#ifdef DEMO_VARIABLE
        fprintf( OUTPUT, "[ FAIL ]\n" );
#endif
        fprintf( OUTPUT, "\nUnable to process MSG2 [%s].\n", __FUNCTION__ );
        print_error_message( ret );
        SAFE_FREE( p_msg2 );
        SAFE_FREE( p_msg3 );
        sgx_destroy_enclave( eid );
        return ret;
    }
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "[ OK ]\n" );
#endif
#ifdef DEBUG_VARIABLE
    fprintf( OUTPUT, "\nSuccessfully processed MSG2\n" );
    debug_print_msg3( p_msg3, msg3_size );
#endif
    /* Sending MSG3 to SP */
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nReady to send Msg3 to SP. Press [RETURN] to continue..\n" );
    getchar( );
#endif
    auto msg3_request = make_shared< Request >( Uri( "http://localhost:8888/remote-attestation" ) );
    msg3_request->set_header( "Accept", "application/json" );
    msg3_request->set_header( "Host", "http://localhost" );
    msg3_request->set_header( "Content-type","application/json" );

    remote_attestation_message_t ra_msg3;
    generate_msg3( &ra_msg3, p_msg3, msg3_size );
    const auto ra_msg3_body = jsoncpp::to_string( ra_msg3 );

    size_t ra_msg3_body_len = ra_msg3_body.size( );

    msg3_request->set_method( "POST" );
    msg3_request->set_body( ra_msg3_body );
    msg3_request->set_header( "Content-Length", std::to_string( ra_msg3_body_len ) );

    /* Getting the response (Attestation result) */
    auto msg3_response = Http::sync( msg3_request );

    attestation_verification_report_t avr;
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nRetrieving Attestation Verification Report from response.. " );
#endif
    ret = retrieve_avr_from_response( msg3_response, &avr );
    if ( SGX_SUCCESS != ret )
    {
#ifdef DEMO_VARIABLE
        fprintf( OUTPUT, "[ FAIL ]\n" );
#endif
        fprintf( OUTPUT, "\nReceived wrong message type!\n");
        SAFE_FREE( p_msg2 );
        SAFE_FREE( p_msg3 );
        sgx_destroy_enclave( eid );
        return -1;
    }
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "[ OK ]\n" );
#endif
#ifdef DEBUG_VARIABLE
    fprintf( OUTPUT, "\nReceived Remote Attestation result!\n" );
#endif
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nVerifying isvEnclaveQuoteStatus.. " );
#endif
    if ( avr.isv_enclave_quote_status.compare( "OK" ) != 0 )
    {
#ifdef DEMO_VARIABLE
        fprintf( OUTPUT, "[ FAIL ]\n" );
#endif
        fprintf( OUTPUT, "\nQuote has not been verified by IAS!\n" );
        SAFE_FREE( p_msg2 );
        SAFE_FREE( p_msg3 );
        sgx_destroy_enclave( eid );
        return -1;
    }
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "[ OK ]\n" );
    fprintf( OUTPUT, "\nRA successfully completed\n");
#endif
#ifdef DEBUG_VARIABLE
    fprintf( OUTPUT, "\nSuccessfully completed attestation process!\n" );
#endif
    completed_attestation_process = true;

    fprintf( OUTPUT, "\nReady to request secret to SP again. Press [RETURN] to continue..\n" );
    getchar( );
    // TODO 5 define server and port as a program parameter
    auto req_secret_msg_request2 = make_shared< Request >( Uri( "http://localhost:8888/remote-attestation" ) );
    req_secret_msg_request2->set_header( "Accept", "application/json" );
    req_secret_msg_request2->set_header( "Host", "http://localhost" );
    req_secret_msg_request2->set_header( "Content-type","application/json" );

    remote_attestation_message_t ra_req_secret_msg_request2;
    generate_req_secret_msg_request( &ra_req_secret_msg_request2 );
    const auto req_secret_msg_request_body2 = jsoncpp::to_string( ra_req_secret_msg_request2 );

    size_t req_secret_msg_request_body_len2 = req_secret_msg_request_body2.size( );

    req_secret_msg_request2->set_method( "POST" );
    req_secret_msg_request2->set_body( req_secret_msg_request_body );
    req_secret_msg_request2->set_header( "Content-Length", std::to_string( req_secret_msg_request_body_len2 ) );

    /* Getting the response (Challenge) */
    auto req_secret_response2 = Http::sync( req_secret_msg_request2, settings );
//    auto req_secret_response2 = Http::sync( req_secret_msg_request2 );
    
    char *p_encrypted_secret = NULL;
    size_t encrypted_secret_size;

#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "\nRetrieving encrypted secret from response.. " );
#endif
    ret = retrieve_encrypted_secret_from_response( req_secret_response2, &p_encrypted_secret, &encrypted_secret_size );

    if ( encrypted_secret_size != ENCRYPTED_SECRET_MAX_LEN )
    {
#ifdef DEMO_VARIABLE
        fprintf( OUTPUT, "[ FAIL ]\n" );
#endif
        fprintf( OUTPUT, "\nReceived secret differs in size. Expected %d, but got %d\n", ENCRYPTED_SECRET_MAX_LEN, encrypted_secret_size );
        return -1;        
    }
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "[ OK ]\n" );
    fprintf( OUTPUT, "\nReceived this (encrypted) secret:\n%s", p_encrypted_secret );
    fprintf( OUTPUT, "\nDecrypting secret inside enclave.. " );
#endif
    ret = enclave_process_encrypted_secret( eid, &status, p_encrypted_secret, encrypted_secret_size, &ra_context, sizeof( sgx_ra_context_t ) );
    if ( SGX_SUCCESS != status )
    {
#ifdef DEMO_VARIABLE
        fprintf( OUTPUT, "[ FAIL ]\n" );
#endif
        print_error_message( status );
        sgx_destroy_enclave( eid );
        SAFE_FREE( p_msg2 );
        SAFE_FREE( p_msg3 );
        SAFE_FREE( p_encrypted_secret );

        return -1;
    }
#ifdef DEMO_VARIABLE
    fprintf( OUTPUT, "[ OK ]\n" );
    ret = enclave_emit_secret( eid );
#endif
    /* Clening up */
    sgx_destroy_enclave( eid );
    SAFE_FREE( p_msg2 );
    SAFE_FREE( p_msg3 );
    SAFE_FREE( p_encrypted_secret );

    printf( "\nEnter a character before exit ...\n" );
    getchar( );

    return ret;
}
