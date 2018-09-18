#include "enclave_t.h"
#include "string.h"
#include "sgx_tkey_exchange.h"
#include <map>
#include "sgx_thread.h" 

sgx_thread_mutex_t mutex;
sgx_ec256_public_t g_b;

std::map<uint32_t, sgx_ra_context_t> contexts_map;
std::map<uint32_t, sgx_ec256_public_t> public_keys_map;
std::map<uint32_t, long> aggregations_map;

uint8_t *decryptedDebug;

void enclave_init_mutex()
{
	sgx_thread_mutex_init(&mutex, NULL);

	decryptedDebug = (uint8_t *) malloc(35);
}

sgx_status_t enclave_ra_init(sgx_ec256_public_t *p_gb, size_t len, sgx_ra_context_t *p_ra_context_out, uint32_t smart_meter_id)
{
	sgx_status_t ret = SGX_SUCCESS;
	int lock_result;
	while ( ( lock_result = sgx_thread_mutex_trylock( &mutex ) ) != 0) continue; 

	sgx_ec256_public_t g_b;
	memcpy(&g_b, p_gb, sizeof(sgx_ec256_public_t));
	public_keys_map.insert( std::pair<uint32_t,sgx_ec256_public_t>(smart_meter_id,g_b) );

	sgx_ra_context_t ra_context;
	ret = sgx_ra_init(p_gb, 0, &ra_context);
	contexts_map.insert( std::pair<uint32_t,sgx_ra_context_t>(smart_meter_id,ra_context) );
	memcpy(p_ra_context_out, &ra_context, sizeof(sgx_ra_context_t));

        sgx_thread_mutex_unlock(&mutex);

	return ret;
}

void enclave_set_g_b(sgx_ec256_public_t *p_gb, size_t len)
{
	memcpy(&g_b, p_gb, len);
}

void enclave_retrieve_g_b(sgx_ec256_public_t *p_g_b)
{
	memcpy(p_g_b, &g_b, sizeof(sgx_ec256_public_t));
}

sgx_status_t enclave_verify_sign_gb_ga(sgx_ec256_signature_t *p_sign_gb_ga, size_t len, uint8_t *p_gb_ga, size_t len_gb_ga, uint32_t smart_meter_id)
{
	if (public_keys_map.find(smart_meter_id) == public_keys_map.end())
	{   
		return SGX_ERROR_INVALID_PARAMETER;
	}
	sgx_status_t ret = SGX_SUCCESS;
	sgx_ecc_state_handle_t ecc_handle;
	uint8_t verify_result = 0;
	ret = sgx_ecc256_open_context(&ecc_handle);
	if (SGX_SUCCESS != ret) return ret;
	ret = sgx_ecdsa_verify(p_gb_ga, len_gb_ga, &public_keys_map.find(smart_meter_id)->second, p_sign_gb_ga, &verify_result, ecc_handle);
	ret = sgx_ecc256_close_context(ecc_handle);
	if (SGX_EC_VALID != verify_result) return SGX_ERROR_INVALID_SIGNATURE;
	return ret;

}

sgx_status_t enclave_get_sk_key(sgx_ra_key_128_t *p_sk_key, uint32_t smart_meter_id)
{
	if (public_keys_map.find(smart_meter_id) == public_keys_map.end())
	{   
		return SGX_ERROR_INVALID_PARAMETER;
	}
	sgx_status_t ret = SGX_SUCCESS;
	ret = sgx_ra_get_keys(contexts_map.find(smart_meter_id)->second, SGX_RA_KEY_SK, p_sk_key);
	return ret;
}
void enclave_destroy_mutex()
{
	sgx_thread_mutex_destroy(&mutex);
}

uint32_t expensive(uint32_t activePower){
    uint64_t variation[8] = { 0x87, 0xBF, 0xBB, 0xF3, 0x38, 0x66, 0x48, 0x48 };
    uint64_t useless;
    for(int i = 0; i < 255; i++){
        for(int j = 0; j < 255; j++){
            useless += (*variation + i) * activePower;
            char * some_pointer = (char *) malloc(200);
            free(some_pointer);
        }


    }

    return useless;
}



void init_aggregator() {
}

void aggregate(char *payload, size_t len) {
	uint32_t smartMeterNumber;
	memcpy(&smartMeterNumber, payload, sizeof(smartMeterNumber));

	payload += 4;
	if (public_keys_map.find(smartMeterNumber) != public_keys_map.end()) {
		sgx_ra_key_128_t p_sk_key;
		sgx_ra_get_keys(contexts_map.find(smartMeterNumber)->second, SGX_RA_KEY_SK, &p_sk_key);

		char decryptedPayload[34 + 1];

		sgx_aes_gcm_128bit_tag_t mac;

		memcpy(&mac, payload + 12, 16);

		if (sgx_rijndael128GCM_decrypt(&p_sk_key, (uint8_t *) payload + 28, 34, (uint8_t *) &decryptedPayload, (uint8_t *) payload, 12, NULL, 0, &mac) != SGX_SUCCESS) {

		} else {
			decryptedPayload[34] = '\0';

			memcpy(decryptedDebug, decryptedPayload, 35);

			strtok(decryptedPayload, ";");

			char *smartMeterIdentifier = strtok(NULL, ";");
			uint32_t time = atoi(strtok(NULL, ";"));
			uint32_t activePower = (uint32_t) strtol(strtok(NULL, ";"), NULL, 16);

			std::map<uint32_t, long>::iterator it = aggregations_map.find(smartMeterNumber);
			if (it != aggregations_map.end()) {
				it->second += activePower;
                expensive(activePower);

			} else {
				aggregations_map.insert(std::pair<uint32_t, long>(smartMeterNumber, activePower));
			}
		}
	}
}

uint8_t *retrieve_decrypted_debug() {
	return decryptedDebug;
}

long retrieve_aggregation(uint32_t smart_meter_id) {
	std::map<uint32_t, long>::iterator it = aggregations_map.find(smart_meter_id);
	return it != aggregations_map.end() ? it->second : 0L;
}
