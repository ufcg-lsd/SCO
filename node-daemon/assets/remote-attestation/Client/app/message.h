#ifndef _MESSAGE_H
#define _MESSAGE_H

#include <inttypes.h>
#include <string.h>
#include "json-cpp.hpp"

#define REQUEST_SECRET_DATA       0
#define CHALLENGE                 1
#define MSG1                      2
#define MSG2                      3
#define MSG3                      4
#define REMOTE_ATTESTATION_RESULT 5
#define SECRET                    6

#define STATUS_OK                    200
#define STATUS_CREATED               201
#define STATUS_UNAUTHORIZED          401
#define STATUS_NOT_FOUND             404
#define STATUS_INTERNAL_SERVER_ERROR 500
#define STATUS_SERVICE_UNAVAILABLE   503

struct remote_attestation_message_t
{
    int message_type;
    std::string payload;
};

// For serialization and deserialization of remote attestation messages to/from JSON string
template<typename X>
inline void serialize( jsoncpp::Stream<X>& stream, remote_attestation_message_t& ra_message )
{
    fields( ra_message, stream, "message_type", ra_message.message_type, "payload", ra_message.payload );
}

struct ias_response_header_t
{
    int response_status;
    int content_length; 
    std::string request_id;
};

struct ias_response_container_t
{
    char *p_response;
    size_t size;
};

struct attestation_evidence_payload_t
{
    std::string isv_enclave_quote;
};

template<typename X>
inline void serialize( jsoncpp::Stream<X>& stream, attestation_evidence_payload_t& aep )
{
    fields( aep, stream, "isvEnclaveQuote", aep.isv_enclave_quote );
}

struct attestation_verification_report_t
{
    std::string report_id;
    std::string isv_enclave_quote_status;
    std::string timestamp;
};

template<typename X>
inline void serialize( jsoncpp::Stream<X>& stream, attestation_verification_report_t& avr )
{
    fields( avr, stream, "isvEnclaveQuoteStatus", avr.isv_enclave_quote_status, "id", avr.report_id, "timestamp", avr.timestamp );
}

#endif
