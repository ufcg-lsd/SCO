#include <stdio.h>
#include <string>
#include <memory>
#include <restbed>
#include <librdkafka/rdkafka.h>
#include <unistd.h>

#include "json-cpp.hpp"
#include "print_utils.h"
#include "base64_utils.h"
#include "string.h"

#include "sgx_urts.h"
#include "enclave_u.h"
#include "sgx_ukey_exchange.h"

#include "app.h"

#include "pthread_pool/pthread_pool.h"

#define ENCLAVE_PATH "enclave.signed.so"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

#define SPID_SIZE 16
#define MAC_KEY_SIZE 16
#define EC_DERIVATION_BUFFER_SIZE(label_length) ((label_length) +4)
#define _T(x) x

using namespace std;
using namespace restbed;

uint8_t smart_meter_spid[SPID_SIZE] = {
	0xCB, 0x83, 0x1C, 0xE1,
	0x94, 0xA3, 0x73, 0x33,
	0x69, 0x57, 0x5A, 0xE6,
	0xE6, 0xE9, 0xDB, 0xEE
};

uint16_t kdf_id = 0x0001;

rd_kafka_topic_t *kafkaTopic;
int kafkaPartition = RD_KAFKA_PARTITION_UA;

int sleepBetweenEachMeasurementMilliseconds;
int intervalBetweenEachMeasurementSeconds;

char attestationUrl[250];
char attestationHost[250];

sgx_status_t derive_key(
		const sgx_enclave_id_t eid,
		const sgx_ec256_dh_shared_t* shared_key,
		const char* label,
		uint32_t label_length,
		sgx_ec_key_128bit_t* derived_key)
{
	sgx_status_t se_ret = SGX_SUCCESS, status = SGX_SUCCESS;
	uint8_t cmac_key[MAC_KEY_SIZE];
	sgx_ec_key_128bit_t key_derive_key;
	if (!shared_key || !derived_key || !label)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	/*check integer overflow */
	if (label_length > EC_DERIVATION_BUFFER_SIZE(label_length))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	memset(cmac_key, 0, MAC_KEY_SIZE);
	se_ret = enclave_compute_cmac(eid, &status,
			(sgx_cmac_128bit_key_t *)cmac_key,
			sizeof(sgx_cmac_128bit_key_t),
			(uint8_t*)shared_key,
			sizeof(sgx_ec256_dh_shared_t),
			(sgx_cmac_128bit_tag_t *)&key_derive_key);
	if (SGX_SUCCESS != se_ret)
	{
		memset(&key_derive_key, 0, sizeof(key_derive_key));
		return se_ret;
	}
	/* derivation_buffer = counter(0x01) || label || 0x00 || output_key_len(0x0080) */
	uint32_t derivation_buffer_length = EC_DERIVATION_BUFFER_SIZE(label_length);
	uint8_t *p_derivation_buffer = (uint8_t *)malloc(derivation_buffer_length);
	if (p_derivation_buffer == NULL)
	{
		return SGX_ERROR_OUT_OF_MEMORY;
	}
	memset(p_derivation_buffer, 0, derivation_buffer_length);

	/*counter = 0x01 */
	p_derivation_buffer[0] = 0x01;
	/*label*/
	memcpy(&p_derivation_buffer[1], label, label_length);
	/*output_key_len=0x0080*/
	uint16_t *key_len = (uint16_t *)&p_derivation_buffer[derivation_buffer_length - 2];
	*key_len = 0x0080;

	se_ret = enclave_compute_cmac(  eid, &status,
			(sgx_cmac_128bit_key_t *)&key_derive_key,
			sizeof(sgx_cmac_128bit_key_t),
			p_derivation_buffer,
			derivation_buffer_length,
			(sgx_cmac_128bit_tag_t *)derived_key);
	memset(&key_derive_key, 0, sizeof(key_derive_key));
	free(p_derivation_buffer);
	return se_ret;
}

sgx_status_t process_msg1(const sgx_enclave_id_t eid, smart_meter_db_item_t *g_smart_meter_db, sgx_ra_msg1_t *p_msg1, sgx_ra_msg2_t **pp_msg2_out)
{
	sgx_status_t ret = SGX_SUCCESS, status = SGX_SUCCESS;

	uint8_t* sig_rl = NULL;
	uint32_t sig_rl_size = 0;

	memcpy(&g_smart_meter_db->g_a, &p_msg1->g_a, sizeof(sgx_ec256_public_t));
	ret = enclave_set_g_a(eid, &status, &p_msg1->g_a, sizeof(sgx_ec256_public_t));
	if (SGX_SUCCESS != status || SGX_SUCCESS != ret) return status;

	ret = enclave_get_b(eid, &status, &g_smart_meter_db->b);

	sgx_ec256_dh_shared_t dh_key;
	memset(&dh_key, 0, sizeof(sgx_ec256_dh_shared_t));
	ret = enclave_get_shared_secret(eid, &status, &dh_key);
	if (SGX_SUCCESS != ret)
	{
		printf("\nFailed to get shared secret!\n");
		return status;
	}

	ret = derive_key(eid, &dh_key, "SMK", (uint32_t)(sizeof("SMK") -1), &g_smart_meter_db->smk_key);
	if(SGX_SUCCESS != ret)
	{
		printf("\nFailed to get SMK!\n");
		return SGX_ERROR_UNEXPECTED;
	}

	ret = derive_key(eid, &dh_key, "MK", (uint32_t)(sizeof("MK") -1), &g_smart_meter_db->mk_key);
	if(SGX_SUCCESS != ret)
	{
		printf("\nFailed to get MK!\n");
		return SGX_ERROR_UNEXPECTED;
	}

	ret = derive_key(eid, &dh_key, "SK", (uint32_t)(sizeof("SK") -1), &g_smart_meter_db->sk_key);
	if(SGX_SUCCESS != ret)
	{
		printf("\nFailed to get SK!\n");
		return SGX_ERROR_UNEXPECTED;
	}
	//#ifdef DEBUG_VARIABLE
	printf("\nSK:\n");
	print_byte_array(&g_smart_meter_db->sk_key, sizeof(sgx_ra_key_128_t));
	//#endif
	ret = derive_key(eid, &dh_key, "VK", (uint32_t)(sizeof("VK") -1), &g_smart_meter_db->vk_key);
	if(SGX_SUCCESS != ret)
	{
		printf("\nFailed to get VK!\n");
		return SGX_ERROR_UNEXPECTED;
	}

	uint32_t msg2_size = sizeof(sgx_ra_msg2_t) + sig_rl_size;
	sgx_ra_msg2_t *p_msg2 = (sgx_ra_msg2_t *) malloc(msg2_size);
	memset(p_msg2, 0, msg2_size);


	// g_b
	ret = enclave_get_g_b(eid, &status, &p_msg2->g_b);

	// SPID
	memcpy(&p_msg2->spid.id, &smart_meter_spid, SPID_SIZE);

	// Quote type
	p_msg2->quote_type = SGX_UNLINKABLE_SIGNATURE;

	// kdf_id
	p_msg2->kdf_id = kdf_id;

	// sign_gb_ga
	ret = enclave_get_sign_gb_ga(eid, &status, &p_msg2->sign_gb_ga);
	if (SGX_SUCCESS != ret) {
		return ret;
	}

	// MAC

	uint8_t *p_mac = (uint8_t *) malloc(SGX_MAC_SIZE);
	uint32_t cmac_size = offsetof(sgx_ra_msg2_t, mac);

	memset(p_mac, 0, SGX_MAC_SIZE);

	ret = enclave_compute_cmac(eid, &status,
			&g_smart_meter_db->smk_key,
			sizeof(sgx_ra_key_128_t),
			(uint8_t *) p_msg2,
			cmac_size,
			(sgx_cmac_128bit_tag_t *) p_mac);

	if (SGX_SUCCESS != ret) return SGX_ERROR_UNEXPECTED;

	memcpy(&p_msg2->mac, p_mac, SGX_MAC_SIZE);

	// sig_rl_size
	p_msg2->sig_rl_size = sig_rl_size;

	// sig_rl
	memcpy(&p_msg2->sig_rl[0], sig_rl, sig_rl_size);

	*pp_msg2_out = p_msg2;

	return ret;
}

/* Helper functions*/

void generate_ra_request_message( int message_type, uint32_t smart_meter_id, void *p_payload, size_t payload_size, remote_attestation_message_t *p_ra_request_message)
{
	size_t encoded_payload_size = payload_size * 2; // Allocating more space than needed
	char *encoded_payload = (char *) malloc(encoded_payload_size);
	memset(encoded_payload, 0, encoded_payload_size);

	base64encode(p_payload, payload_size, encoded_payload, encoded_payload_size);
	std::string encoded_payload_str(encoded_payload);

	remote_attestation_message_t ra_response_message{ message_type, smart_meter_id, encoded_payload_str };

	*p_ra_request_message = ra_response_message;

	SAFE_FREE(encoded_payload);
}


void generate_msg0( sgx_enclave_id_t eid, uint32_t smart_meter_id, remote_attestation_message_t *p_ra_msg0 )
{
	sgx_status_t status;
	/* Retrieving g_b */
	sgx_ec256_public_t g_b;
	enclave_get_g_b(eid, &status, &g_b);

	print_byte_array(&g_b, sizeof(sgx_ec256_public_t));
	printf("\n");

	generate_ra_request_message( MSG0, smart_meter_id, (char *) &g_b, sizeof(sgx_ec256_public_t), p_ra_msg0);
}

void generate_msg2( remote_attestation_message_t *p_ra_msg2, uint32_t sm_id, sgx_ra_msg2_t *p_msg2 )
{
	generate_ra_request_message( MSG2, sm_id, p_msg2, sizeof(sgx_ra_msg2_t), p_ra_msg2);
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

	SAFE_FREE( encoded_payload );

}

sgx_status_t retrieve_msg1_from_response( const shared_ptr< Response >& response, uint32_t *p_sm_id, sgx_ra_msg1_t *p_msg1 )
{
	if ( response->get_header( "Content-Type", String::lowercase ) == "application/json" )
	{
		if ( response->has_header( "Content-Length" ) )
		{
			auto response_body_size = response->get_header( "Content-Length", 0 );
			Http::fetch( response_body_size, response );

			const auto response_body = response->get_body( );

			remote_attestation_message_t ra_msg1;

			std::string response_body_str(response_body.begin(), response_body.end());
			jsoncpp::parse(ra_msg1, response_body_str);

			*p_sm_id = ra_msg1.smart_meter_id;

			if (ra_msg1.message_type != MSG1) return SGX_ERROR_UNEXPECTED;

			size_t decoded_payload_size;
			uint8_t *p_decoded_payload = NULL;

			decode_ra_message_payload( &ra_msg1, &p_decoded_payload, &decoded_payload_size );

			memcpy(p_msg1, p_decoded_payload, sizeof(sgx_ra_msg1_t));
			SAFE_FREE(p_decoded_payload);
			return SGX_SUCCESS;
		}
		else
		{
			printf("\nWrong response format!\n");
			return SGX_ERROR_UNEXPECTED;
		}
	}
	else
	{
		printf("\nWrong response type!\n");
		return SGX_ERROR_UNEXPECTED;
	}
}

sgx_status_t retrieve_msg3_from_response( const shared_ptr< Response >& response, sgx_ra_msg3_t *p_msg3 )
{
	if ( response->get_header( "Content-Type", String::lowercase ) == "application/json" )
	{
		if ( response->has_header( "Content-Length" ) )
		{
			auto response_body_size = response->get_header( "Content-Length", 0 );
			Http::fetch( response_body_size, response );

			const auto response_body = response->get_body( );

			remote_attestation_message_t ra_msg3;

			std::string response_body_str(response_body.begin(), response_body.end());
			jsoncpp::parse(ra_msg3, response_body_str);

			if (ra_msg3.message_type != MSG3) return SGX_ERROR_UNEXPECTED;

			size_t decoded_payload_size;
			uint8_t *p_decoded_payload = NULL;

			decode_ra_message_payload( &ra_msg3, &p_decoded_payload, &decoded_payload_size );

			memcpy(p_msg3, p_decoded_payload, sizeof(sgx_ra_msg3_t));
			SAFE_FREE(p_decoded_payload);
			return SGX_SUCCESS;
		}
		else
		{
			printf("\nWrong response format!\n");
			return SGX_ERROR_UNEXPECTED;
		}
	}
	else
	{
		printf("\nWrong response type!\n");
		return SGX_ERROR_UNEXPECTED;
	}
}

void *sendMeasurements(void *arg)
{
        int smartMeterNumber = *((int *) arg);

	FILE* OUTPUT = stdout;
	sgx_enclave_id_t eid;
	smart_meter_db_item_t g_smart_meter_db;
	sgx_status_t ret = SGX_SUCCESS;
	int updated = 0;
	sgx_launch_token_t launch_token;

	/* Enclave creation */
	memset(&launch_token, 0, sizeof(sgx_launch_token_t));
	ret = sgx_create_enclave(_T(ENCLAVE_PATH),
			SGX_DEBUG_FLAG,
			&launch_token,
			&updated,
			&eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		fprintf(OUTPUT, "\nError, call sgx_create_enclave fail [%s].",
				__FUNCTION__);
		return NULL;
	}
	fprintf(OUTPUT, "\nCall sgx_create_enclave success.\n");

	/* Generating HTTP request to start remote attestation*/
	auto request_msg0 = make_shared< Request >( Uri( attestationUrl ) );
	request_msg0->set_header( "Accept", "application/json" );
	request_msg0->set_header( "Host", attestationHost );
	request_msg0->set_header("Content-type","application/json");

	remote_attestation_message_t ra_msg0;
	generate_msg0(eid, smartMeterNumber, &ra_msg0);
	const auto msg0_body = jsoncpp::to_string(ra_msg0);

	size_t msg0_body_len = msg0_body.size();

	request_msg0->set_method("POST");
	request_msg0->set_body(msg0_body);
	request_msg0->set_header("Content-Length", std::to_string(msg0_body_len));

	/* Getting the response (MSG1) */
	auto response_msg1 = Http::sync( request_msg0 );

	uint32_t sm_id;
	sgx_ra_msg1_t msg1;

	retrieve_msg1_from_response( response_msg1, &sm_id, &msg1 );

	/* Generating MSG2 */
	sgx_ra_msg2_t *p_msg2 = NULL;
	ret = process_msg1(eid, &g_smart_meter_db, &msg1, &p_msg2);
	if (SGX_SUCCESS != ret) printf("\nUnable to process MSG1 correctly\n");

	/* Generating HTTP request to generate quote */
	auto request_msg2 = make_shared< Request >( Uri( attestationUrl ) );
	request_msg2->set_header( "Accept", "application/json" );
	request_msg2->set_header( "Host", attestationHost );
	request_msg2->set_header("Content-type","application/json");

	remote_attestation_message_t ra_msg2;
	generate_msg2(&ra_msg2, sm_id, p_msg2);
	const auto msg2_body = jsoncpp::to_string(ra_msg2);

	size_t msg2_body_len = msg2_body.size();

	request_msg2->set_method("POST");
	request_msg2->set_body(msg2_body);
	request_msg2->set_header("Content-Length", std::to_string(msg2_body_len));

	/* Getting the response (MSG3) */
	auto response_msg3 = Http::sync( request_msg2 );

	sgx_ra_msg3_t msg3;
	retrieve_msg3_from_response( response_msg3, &msg3 );

	/* Emitting QUOTE */
	uint32_t sig_len = *((uint32_t *)(((uint8_t *)&msg3.quote)+432));
#ifdef DEBUG_VARIABLE
	fprintf(OUTPUT, "\nsig_len: \n");
	print_byte_array(&sig_len,4);
#endif

	uint32_t quote_size = 436 + sig_len;
#ifdef DEBUG_VARIABLE
	fprintf(OUTPUT, "\nquote_size: \n");
	print_byte_array(&quote_size,4);
#endif        

	// TODO Rodolfo
	/* Add here the code to use IAS when checking for the RA of QUOTE         */
	/*                                                                        */

	// TODO Leandro

	/* Generate Smart Meter measurements here!!!                              */
	/* Use smart_meter_id when sending data to aggregator so that it can
	 * retrieve the context used when retrieving the symmetric key            */

	/*                                                                        */

	char buffer[128];
	char encryptedBuffer[512];

	FILE *urandom = fopen ("/dev/urandom", "r");
	setvbuf (urandom, NULL, _IONBF, 0);  // turn off buffering

	// setup state buffer
	unsigned short randstate[3];
	// fgetc() returns a `char`, we need to fill a `short`
	randstate[0] = (fgetc (urandom) << 8) | fgetc (urandom);
	randstate[1] = (fgetc (urandom) << 8) | fgetc (urandom);
	randstate[2] = (fgetc (urandom) << 8) | fgetc (urandom);

	// cleanup urandom
	fclose (urandom);

	int i = 0;
	while (true) {
		int activePower = erand48(randstate) * MAX_ACTIVE_POWER;

		sprintf(buffer, "SINGLE;medidor%08d;%08d;%02X", smartMeterNumber, i, activePower);

		sgx_status_t result;
		encryptData(eid, &result, &g_smart_meter_db.sk_key, 16, (uint8_t *) &buffer, strlen(buffer), ((uint8_t *) &encryptedBuffer) + sizeof(smartMeterNumber), sizeof(encryptedBuffer) - sizeof(smartMeterNumber));

		memcpy(&encryptedBuffer, &smartMeterNumber, sizeof(smartMeterNumber));

//		if (result == SGX_SUCCESS) {
//			print_byte_array(encryptedBuffer, 128);
//		}

		printf("%s - ActivePower: %d\n", buffer, activePower);
		while (rd_kafka_produce(kafkaTopic, kafkaPartition, RD_KAFKA_MSG_F_COPY, &encryptedBuffer, strlen(buffer) + 28 + 4, NULL, 0, NULL) != 0);
		i += intervalBetweenEachMeasurementSeconds;
		usleep(sleepBetweenEachMeasurementMilliseconds * 1000);
	}

	sgx_destroy_enclave(eid);

	return 0;
}

int main(int argc, char ** argv)
{
	if (argc < 6) {
		fprintf(stderr, "Syntax: <kafka-bootstrap-servers> <region> <smart-meters-count> <sleep-between-each-measurement-milliseconds> <interval-between-each-measurement-seconds> [<attestation-server-host> <attestation-server-port>]\n");
		exit(1);
	}

	char *brokers = argv[1];
	char *topic = argv[2];
	int smartMetersCount = atoi(argv[3]);
	sleepBetweenEachMeasurementMilliseconds = atoi(argv[4]);
	intervalBetweenEachMeasurementSeconds = atoi(argv[5]);

	

	sprintf(attestationUrl, "http://localhost:8888/remote-attestation");
	sprintf(attestationHost, "http://localhost");

	if (argc > 6) {
		int attestationPort = 8888;

		if (argc == 8) {
			attestationPort = atoi(argv[7]);
		}

		sprintf(attestationUrl, "http://%s:%d/remote-attestation", argv[6], attestationPort);
		sprintf(attestationHost, "http://%s", argv[6]);
	}

	srand(time(NULL));

	char errorString[512];
	char buffer[2048];
	rd_kafka_resp_err_t kafkaError;
	rd_kafka_conf_t *kafkaConfig;
	rd_kafka_topic_conf_t *topicConfig;
	rd_kafka_t *kafka;

	kafkaConfig = rd_kafka_conf_new();
	topicConfig = rd_kafka_topic_conf_new();

	if (!(kafka = rd_kafka_new(RD_KAFKA_PRODUCER, kafkaConfig, errorString, sizeof(errorString)))) {
		fprintf(stderr, "%% Failed to create new producer: %s\n", errorString);
		exit(3);
	}

	if (rd_kafka_brokers_add(kafka, brokers) == 0) {
		fprintf(stderr, "%% No valid brokers specified\n");
		exit(4);
	}

	kafkaTopic = rd_kafka_topic_new(kafka, topic, topicConfig);
	topicConfig = NULL;

	void *threadPool = pool_start(sendMeasurements, smartMetersCount);


	int *smartMeterNumber;
	for (int i = 0; i < smartMetersCount; i++) {
		smartMeterNumber = (int *)malloc(sizeof(int));
		*smartMeterNumber = rand() / 1000;

		pool_enqueue(threadPool, smartMeterNumber, 1);
	}

	pool_wait(threadPool);

	while (rd_kafka_outq_len(kafka) > 0) {
		rd_kafka_poll(kafka, 50);
	}

	rd_kafka_destroy(kafka);
	rd_kafka_wait_destroyed(5000);

	return 0;
}
