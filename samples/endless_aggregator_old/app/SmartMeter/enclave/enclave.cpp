#include "enclave_t.h"
#include "string.h"

sgx_ec256_private_t *p_b = NULL;
sgx_ec256_public_t *p_g_b = NULL;
sgx_ec256_public_t *p_g_a = NULL;
uint8_t *p_gb_ga = NULL;
sgx_ecc_state_handle_t *p_ecc_handle = NULL;
sgx_ec256_dh_shared_t *p_shared_key = NULL;

/* Internal functions */

sgx_status_t generate_handle()
{
	sgx_status_t ret;
	p_ecc_handle = (sgx_ecc_state_handle_t *) malloc(sizeof(sgx_ecc_state_handle_t));
	ret = sgx_ecc256_open_context(p_ecc_handle);
	return ret;
}

sgx_status_t generate_keys()
{
	sgx_status_t ret = SGX_SUCCESS;
	p_b = (sgx_ec256_private_t *) malloc(sizeof(sgx_ec256_private_t));
	p_g_b = (sgx_ec256_public_t *) malloc(sizeof(sgx_ec256_public_t));
	int retries = 2;
	while (retries-- && (NULL == p_ecc_handle || SGX_SUCCESS != ret))
	{
		ret = generate_handle();
	}
	if (SGX_SUCCESS != ret) return ret;

	ret = sgx_ecc256_create_key_pair(p_b, p_g_b, *p_ecc_handle);
	return ret;
}

/* ECalls*/

sgx_status_t enclave_set_g_a(sgx_ec256_public_t *p_g_a_in, size_t len)
{
	sgx_status_t ret = SGX_SUCCESS;
	if (NULL == p_g_a) p_g_a = (sgx_ec256_public_t *) malloc(sizeof(sgx_ec256_public_t));
	memcpy(p_g_a, p_g_a_in, sizeof(sgx_ec256_public_t));
	return ret;
}


sgx_status_t enclave_get_g_a(sgx_ec256_public_t *p_g_a_out)
{
	sgx_status_t ret = SGX_SUCCESS;
	if (NULL == p_g_a) return SGX_ERROR_UNEXPECTED;
	memcpy(p_g_a_out, p_g_a, sizeof(sgx_ec256_public_t));
	return ret;
}

sgx_status_t enclave_get_b(sgx_ec256_private_t *p_b_out)
{
	sgx_status_t ret = SGX_SUCCESS;
	int retries = 2;
	while (retries-- && (NULL == p_b || NULL == p_g_b || SGX_SUCCESS != ret))
	{
		ret = generate_keys();
	}
	memcpy(p_b_out, p_b, sizeof(sgx_ec256_private_t));
	return ret;
}

sgx_status_t enclave_get_g_b(sgx_ec256_public_t *p_gb_out)
{
	sgx_status_t ret = SGX_SUCCESS;
	int retries = 2;
	while (retries-- && (NULL == p_b || NULL == p_g_b || SGX_SUCCESS != ret))
	{
		ret = generate_keys();
	}
	memcpy(p_gb_out, p_g_b, sizeof(sgx_ec256_public_t));
	return ret;
}

sgx_status_t enclave_get_sign_gb_ga(sgx_ec256_signature_t *p_sign_gb_ga)
{
	sgx_status_t ret = SGX_SUCCESS;
	size_t gb_ga_size = 2 * sizeof(sgx_ec256_public_t);
	size_t gb_size = sizeof(sgx_ec256_public_t);
	p_gb_ga = (uint8_t *) malloc(gb_ga_size);
	memcpy(p_gb_ga, p_g_b, gb_size);
	memcpy(p_gb_ga+gb_size, p_g_a, gb_size);
	ret = sgx_ecdsa_sign(p_gb_ga, gb_ga_size, p_b, p_sign_gb_ga, *p_ecc_handle);
	return ret;
}

sgx_status_t enclave_get_gb_ga(uint8_t *p_gb_ga_out, size_t len)
{
	sgx_status_t ret = SGX_SUCCESS;
	if (NULL == p_gb_ga) return SGX_ERROR_UNEXPECTED;
	memcpy(p_gb_ga_out, p_gb_ga, len);
	return ret;
}

sgx_status_t enclave_get_shared_secret(sgx_ec256_dh_shared_t *p_shared_secret_out)
{
	sgx_status_t ret = SGX_SUCCESS;
	if (NULL == p_g_a || NULL == p_ecc_handle) return SGX_ERROR_UNEXPECTED;
	int retries = 2;
	while (retries-- && (NULL == p_b || NULL == p_g_b || SGX_SUCCESS != ret))
	{
		ret = generate_keys();
	}

	ret = sgx_ecc256_compute_shared_dhkey(p_b, p_g_a, p_shared_secret_out, *p_ecc_handle);
	return ret;
}

sgx_status_t enclave_compute_cmac( sgx_cmac_128bit_key_t *cmac_key,
		size_t                 key_len,
		uint8_t               *p_src,
		size_t                 src_len,
		sgx_cmac_128bit_tag_t *p_mac )
{
	sgx_status_t ret = SGX_SUCCESS;
	ret = sgx_rijndael128_cmac_msg(cmac_key, p_src, src_len, p_mac);
	return ret;
}

sgx_status_t encryptData(sgx_aes_gcm_128bit_key_t *p_key, size_t p_key_len, uint8_t *data, size_t data_len, uint8_t *buffer, size_t buffer_len) {
	if (sgx_read_rand(buffer, 12) != SGX_SUCCESS)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	sgx_aes_gcm_128bit_tag_t mac;

	sgx_status_t result = sgx_rijndael128GCM_encrypt(p_key, data, data_len, buffer + 28, buffer, 12, NULL, 0, &mac);

	if (result == SGX_SUCCESS) {
		memcpy(buffer + 12, &mac, sizeof(mac));
	}

	return SGX_SUCCESS;
}
