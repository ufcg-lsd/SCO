#include <stdio.h>
#include <string>
#include <memory>
#include <restbed>
#include <librdkafka/rdkafka.h>
#include <pthread.h>
#include <unistd.h>
#include <chrono>
#include <fstream>

#include "json-cpp.hpp"
#include "print_utils.h"
#include "base64_utils.h"
#include "string.h"
#include <map>
#include "sgx_urts.h"
#include "enclave_u.h"
#include "sgx_ukey_exchange.h"


#define ENCLAVE_PATH "enclave.signed.so"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

#define _T(x) x

using namespace std;
using namespace restbed;

sgx_enclave_id_t eid;
std::map<uint32_t, sgx_ra_context_t> contexts_map;
std::map<uint32_t, sgx_ec256_public_t> public_keys_map;
std::map<uint32_t, sgx_ec256_public_t> ga_map; // for debugging purposes only
std::map<uint32_t, uint32_t> number_of_measurements_map;
Service service;

/* Functions declaration*/
void post_method_handler( const shared_ptr< Session > );
void decode_ra_message_payload( remote_attestation_message_t *p_ra_message, uint8_t **pp_decoded_payload, size_t *p_decoded_size);
void generate_ra_response_message( int message_type, uint8_t *p_payload, size_t payload_size, remote_attestation_message_t *p_ra_response_message);
sgx_status_t handle_msg0( remote_attestation_message_t *ra_message, remote_attestation_message_t *p_ra_response_message );
sgx_status_t handle_msg2( remote_attestation_message_t *ra_message, remote_attestation_message_t *p_ra_response_message );
void* initKafka(void *arg);

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
}

void generate_ra_response_message( int message_type, uint32_t smart_meter_id, char *p_payload, size_t payload_size, remote_attestation_message_t *p_ra_response_message)
{
	size_t encoded_payload_size = payload_size * 2; // Allocating more space than needed
	char *encoded_payload = (char *) malloc(encoded_payload_size);
	memset(encoded_payload, 0, encoded_payload_size);

	base64encode(p_payload, payload_size, encoded_payload, encoded_payload_size);
	std::string encoded_payload_str(encoded_payload);

	remote_attestation_message_t ra_response_message{ message_type, smart_meter_id, encoded_payload_str };

	*p_ra_response_message = ra_response_message;

	SAFE_FREE(encoded_payload);
}

sgx_status_t retrieve_msg2_from_ra_message( remote_attestation_message_t *p_ra_message, uint32_t *p_sm_id, sgx_ra_msg2_t *p_msg2 )
{
	*p_sm_id = p_ra_message->smart_meter_id;

	if (p_ra_message->message_type != MSG2) return SGX_ERROR_UNEXPECTED;

	size_t decoded_payload_size;
	uint8_t *p_decoded_payload = NULL;

	decode_ra_message_payload( p_ra_message, &p_decoded_payload, &decoded_payload_size );

	memcpy(p_msg2, p_decoded_payload, sizeof(sgx_ra_msg2_t));
	SAFE_FREE(p_decoded_payload);
	return SGX_SUCCESS;
}


/* Handling POST requests */
void post_method_handler( const shared_ptr< Session > session )
{
	const auto request = session->get_request( );

	if ( request->get_header( "Content-Type", String::lowercase ) == "application/json" )
	{   
                    printf("[DEBUG] Entering time record\n");
                    using namespace std::chrono;
                    milliseconds ms = duration_cast< milliseconds >(
                       system_clock::now().time_since_epoch()
                       );
                    std::ofstream outfile ("/usr/src/att_request.dat");

                    outfile << std::to_string(ms.count()) << std::endl;
                    outfile.close();

		if ( request->has_header( "Content-Length" ) ) 
		{
			int length = request->get_header( "Content-Length", 0 );
			session->fetch( length, [ ]( const shared_ptr< Session > session, const Bytes& )
					{
					sgx_status_t ret = SGX_SUCCESS;
					const auto request = session->get_request( );
					const auto body = request->get_body( );

					remote_attestation_message_t ra_message, ra_response_message;

					std::string str_body(body.begin(), body.end());
					jsoncpp::parse(ra_message, str_body);

					// Starting Remote Attestation process
					if (MSG0 == ra_message.message_type)
					{
					ret = handle_msg0( &ra_message, &ra_response_message );
					if (SGX_SUCCESS != ret) session->close( BAD_REQUEST );
					}
					// Generate quote
					else if (MSG2 == ra_message.message_type)
					{
					ret = handle_msg2( &ra_message, &ra_response_message );
					if (SGX_SUCCESS != ret) session->close( BAD_REQUEST );
					}
					else
					{
						session->close( BAD_REQUEST );
					}

					const auto response_body = jsoncpp::to_string(ra_response_message);
					size_t response_body_len = response_body.size();

					session->set_header( "Accept", "application/json" );
					session->set_header( "Host", "http://localhost" );
					session->set_header("Content-Type", "application/json");
					session->set_header("Content-Length", std::to_string(response_body_len));

					session->close( OK, response_body );
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

/* Handling MSG0 and producing MSG1 */
sgx_status_t handle_msg0( remote_attestation_message_t *p_ra_message, remote_attestation_message_t *p_ra_response_message )
{
	sgx_status_t ret = SGX_SUCCESS, status = SGX_SUCCESS;

	size_t decoded_size;
	uint8_t *p_decoded_payload = NULL;

	decode_ra_message_payload( p_ra_message, &p_decoded_payload, &decoded_size );

	sgx_ec256_public_t g_b;
	memset(&g_b, 0, sizeof(sgx_ec256_public_t));
	memcpy(&g_b, p_decoded_payload, sizeof(sgx_ec256_public_t));

	#ifdef DEBUG_VARIABLE
	print_byte_array(&g_b, sizeof(sgx_ec256_public_t));
	#endif

	uint32_t smart_meter_id = p_ra_message->smart_meter_id;

	printf("Receiving connection from Smart Meter: %08d\n", smart_meter_id);

	sgx_ra_context_t ra_context;
//	ret = enclave_ra_init(eid, &status, &g_b, sizeof(sgx_ec256_public_t), &ra_context, smart_meter_id);

	while (enclave_ra_init(eid, &status, &g_b, sizeof(sgx_ec256_public_t), &ra_context, smart_meter_id) != SGX_SUCCESS) {
		printf("\nError trying to init remote attestation\n");
		print_error_message(ret);
	}

	public_keys_map.insert( std::pair<uint32_t,sgx_ec256_public_t>(smart_meter_id,g_b) );
	contexts_map.insert( std::pair<uint32_t,sgx_ra_context_t>(smart_meter_id,ra_context) );

//	printf("Tamanho atual do mapa: %d\n", public_keys_map.size());

	sgx_ra_msg1_t msg1;
	memset(&msg1, 0, sizeof(sgx_ra_msg1_t));
	ret = sgx_ra_get_msg1(ra_context,
			eid,
			sgx_ra_get_ga,
			&msg1
			);  

	ga_map.insert( std::pair<uint32_t,sgx_ec256_public_t>(smart_meter_id,msg1.g_a) );
	generate_ra_response_message( MSG1, smart_meter_id, (char *) &msg1, sizeof(sgx_ra_msg1_t), p_ra_response_message);

	return ret;
}

/* Handling MSG2 and producing MSG3 */
sgx_status_t handle_msg2(remote_attestation_message_t *p_ra_message, remote_attestation_message_t *p_ra_response_message )
{
	FILE* OUTPUT = stdout;
	sgx_status_t ret = SGX_SUCCESS, status = SGX_SUCCESS;

	size_t decoded_size;
	uint8_t *p_decoded_payload = NULL;

	uint32_t smart_meter_id;
	sgx_ra_msg2_t msg2;

	ret = retrieve_msg2_from_ra_message( p_ra_message, &smart_meter_id, &msg2);
	if (SGX_SUCCESS != ret)
	{
		printf("\nWrong message type received\n");
		print_error_message(ret);
	}

	if (contexts_map.find(smart_meter_id) == contexts_map.end())
	{
		printf("\nThis smart meter id is not registered!\n");
		return SGX_ERROR_UNEXPECTED;
	}

	// XXX Debugging
#ifdef DEBUG_VARIABLE
	size_t gb_ga_size = 2 * sizeof(sgx_ec256_public_t);
	uint8_t *p_gb_ga = (uint8_t *) malloc(gb_ga_size);
	memset(p_gb_ga, 0 , gb_ga_size);
	memcpy(p_gb_ga, &msg2.g_b, sizeof(sgx_ec256_public_t));
	memcpy(p_gb_ga, &ga_map.find(smart_meter_id)->second, sizeof(sgx_ec256_public_t));

	ret = enclave_verify_sign_gb_ga(eid, &status, &msg2.sign_gb_ga, sizeof(sgx_ec256_signature_t), p_gb_ga, gb_ga_size, smart_meter_id);
	if (SGX_SUCCESS != status)
	{
		printf("\nsign_gb_ga was not verified correctly\n");
		print_error_message(status);
	}
#endif
	uint32_t msg3_size = 0;
	sgx_ra_msg3_t *p_msg3 = NULL;

	sgx_ra_context_t ra_context = contexts_map.find(smart_meter_id)->second; 
	ret = sgx_ra_proc_msg2(ra_context, // retrieved from map
			eid,
			sgx_ra_proc_msg2_trusted,
			sgx_ra_get_msg3_trusted,
			&msg2,
			sizeof(sgx_ra_msg2_t),
			&p_msg3,
			&msg3_size
			);
	if (SGX_SUCCESS != ret)
	{
		fprintf(OUTPUT, "\nUnable to process Msg2 [%s].\n", __FUNCTION__);
		print_error_message(ret);
		return ret;
	}
//	fprintf(OUTPUT, "\nSuccessfully processed Msg2.\n");

	sgx_ra_key_128_t sk_key;
	enclave_get_sk_key(eid, &status, &sk_key, smart_meter_id);
	#ifdef DEBUG_VARIABLE
	if (SGX_SUCCESS != status)
	{
		printf("Unable to retrieve SK KEY!");
	}
	else
	{
		printf("\nSK Key:\n");
		print_byte_array(&sk_key, sizeof(sgx_ra_key_128_t));
	}
	#endif    
	generate_ra_response_message( MSG3, smart_meter_id, (char *) p_msg3, sizeof(sgx_ra_msg3_t), p_ra_response_message );

	return ret;
}

void* initKafka(void *arg)
{
	char **argv = (char **) arg;
	char *brokers = argv[1];
	char *topic = argv[2];
	int numberOfMeasurementsToAggregate = atoi(argv[3]);

	char errorString[512];
	rd_kafka_resp_err_t kafkaError;
	rd_kafka_conf_t *kafkaConfig;
	rd_kafka_topic_conf_t *topicConfig;
	rd_kafka_t *kafka;
	rd_kafka_topic_partition_list_t *kafkaTopics;

	kafkaConfig = rd_kafka_conf_new();
	topicConfig = rd_kafka_topic_conf_new();

	if (rd_kafka_conf_set(kafkaConfig, "group.id", "group-region-consumption-aggregator", errorString, sizeof(errorString)) != RD_KAFKA_CONF_OK) {
		fprintf(stderr, "%% %s\n", errorString);
		exit(2);
	}

	if (!(kafka = rd_kafka_new(RD_KAFKA_CONSUMER, kafkaConfig, errorString, sizeof(errorString)))) {
		fprintf(stderr, "%% Failed to create new consumer: %s\n", errorString);
		exit(3);
	}

	if (rd_kafka_brokers_add(kafka, brokers) == 0) {
		fprintf(stderr, "%% No valid brokers specified\n");
		exit(4);
	}

	rd_kafka_poll_set_consumer(kafka);

	kafkaTopics = rd_kafka_topic_partition_list_new(1);
	rd_kafka_topic_partition_list_add(kafkaTopics, topic, 0);

	if ((kafkaError = rd_kafka_assign(kafka, kafkaTopics))) {
		fprintf(stderr, "%% Failed to start consuming topics: %s\n", rd_kafka_err2str(kafkaError));
		exit(5);
	}

	init_aggregator(eid);

    int check = 0;
	while (true) {
		rd_kafka_message_t *kafkaMessage;

		//              printf("Polling...\n");
		kafkaMessage = rd_kafka_consumer_poll(kafka, 1000);

		if (kafkaMessage) {
            
			if (!kafkaMessage->err) {
                    if (check == 0) {
                        printf("[DEBUG] Entering time record\n");
                        using namespace std::chrono;
                        milliseconds ms = duration_cast< milliseconds >(
                           system_clock::now().time_since_epoch()
                           );
                        std::ofstream outfile ("/usr/src/att_records.dat");
                        printf("[DEBUG] ms is: %d", ms.count());
                        outfile << std::to_string(ms.count()) << std::endl;
                        outfile.close();
                        check = 1;
                    }
				char *payload = (char *)malloc(kafkaMessage->len + 1);
				memcpy(payload, kafkaMessage->payload, (size_t) kafkaMessage->len);
				payload[kafkaMessage->len] = '\0';

				while (aggregate(eid, payload, kafkaMessage->len + 1) != SGX_SUCCESS);

			        int smartMeterNumber;
			        memcpy(&smartMeterNumber, payload, sizeof(smartMeterNumber));

				if (public_keys_map.find(smartMeterNumber) == public_keys_map.end()) {
					continue;
				}

				long int aggregation = 0L;
				retrieve_aggregation(eid, &aggregation, smartMeterNumber);

				std::map<uint32_t, uint32_t>::iterator it = number_of_measurements_map.find(smartMeterNumber);
				uint32_t numberOfMeasurements = 0;

				if (it != number_of_measurements_map.end()) {
					numberOfMeasurements = it->second;
				}

				numberOfMeasurements++;

				if (numberOfMeasurements == numberOfMeasurementsToAggregate) {
					printf("Smart Meter %08d => ActivePower[%08ld]\n", smartMeterNumber, aggregation);
					numberOfMeasurements = 0;
				}

				if (it == number_of_measurements_map.end()) {
					number_of_measurements_map.insert(std::make_pair(smartMeterNumber, numberOfMeasurements));
				} else {
					it->second = numberOfMeasurements;
				}

//				uint8_t *decryptedDebug;
//				retrieve_decrypted_debug(eid, &decryptedDebug);
//				print_byte_array(decryptedDebug, 35);
//				printf("%s\n", (char *)decryptedDebug);

			} else {
				if (kafkaMessage->err != RD_KAFKA_RESP_ERR__PARTITION_EOF) {
					fprintf(stderr, "%% Error receiving message: %d\n", kafkaMessage->err);
				}
			}

			rd_kafka_message_destroy(kafkaMessage);

			//                      printf("Consumed/Expected: %d/%d\n", consumed, aggregationTotal);
		}

		//              printf("Polled...\n");

	}

//	printf("Will print the aggregations now...\n");

//	long *aggregations = (long *) malloc(((durationSeconds / intervalBetweenEachMeasurementSeconds) + 1) * sizeof(long));;
//	retrieve_aggregations(eid, aggregations, ((durationSeconds / intervalBetweenEachMeasurementSeconds) + 1) * sizeof(long));

//	for (int i = 0; i < ((durationSeconds / intervalBetweenEachMeasurementSeconds) + 1); i++) {
//		printf("%d => %ld\n", i * intervalBetweenEachMeasurementSeconds, aggregations[i]);
//	}

	rd_kafka_consumer_close(kafka);

	rd_kafka_topic_partition_list_destroy(kafkaTopics);

	rd_kafka_destroy(kafka);

	service.stop();

	return NULL;
}

/* main */
int main(int argc, char **argv)
{
	if (argc != 4) {
		fprintf(stderr, "Syntax: <kafka-bootstrap-servers> <region> <number-of-measurements-to-aggregate>\n");
		exit(1);
    }

	FILE* OUTPUT = stdout;
	sgx_status_t ret = SGX_SUCCESS, status;
	int updated = 0;
	sgx_launch_token_t launch_token;

	/*  #######################################################
#                  Enclave creation                   #
	 *///#######################################################

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
		return -1;
	}
	fprintf(OUTPUT, "\nCall sgx_create_enclave success.\n");

	enclave_init_mutex(eid);
	
	// Kafka part
	pthread_t kafkaThread;
	pthread_create(&kafkaThread, NULL, initKafka, argv);

	/*  #######################################################
#                Starting REST server                 #
	 *///#######################################################

	auto resource = make_shared< Resource >( );
	resource->set_path("/remote-attestation");
	resource->set_method_handler("POST", { { "Accept", "application/json" }, { "Content-Type", "application/json" } }, &post_method_handler );

	auto settings = make_shared< Settings >( );
	settings->set_port( 8888 );
	settings->set_default_header( "Connection", "close" );

	unsigned int num_threads = 1;
	settings->set_worker_limit( num_threads );
	settings->set_connection_limit( num_threads );

	service.publish( resource );
	service.start( settings );

	/*  #######################################################
#                    Cleaning up                      #
	 *///#######################################################

	enclave_destroy_mutex(eid);
	sgx_destroy_enclave(eid);

	//	printf("\nEnter a character before exit ...\n");
	//	getchar();

	return ret;

}
