#include "enclave_u.h"
#include <errno.h>


typedef struct ms_enclave_ra_init_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t* ms_p_gb;
	size_t ms_len;
	sgx_ra_context_t* ms_p_ra_context_out;
	uint32_t ms_smart_meter_id;
} ms_enclave_ra_init_t;

typedef struct ms_enclave_set_g_b_t {
	sgx_ec256_public_t* ms_p_gb;
	size_t ms_len;
} ms_enclave_set_g_b_t;

typedef struct ms_enclave_retrieve_g_b_t {
	sgx_ec256_public_t* ms_p_g_b;
} ms_enclave_retrieve_g_b_t;

typedef struct ms_enclave_verify_sign_gb_ga_t {
	sgx_status_t ms_retval;
	sgx_ec256_signature_t* ms_p_sign_gb_ga;
	size_t ms_len;
	uint8_t* ms_p_gb_ga;
	size_t ms_len_gb_ga;
	uint32_t ms_sm_id;
} ms_enclave_verify_sign_gb_ga_t;

typedef struct ms_enclave_get_sk_key_t {
	sgx_status_t ms_retval;
	sgx_ra_key_128_t* ms_p_sk_key;
	uint32_t ms_sm_id;
} ms_enclave_get_sk_key_t;



typedef struct ms_aggregate_t {
	char* ms_payload;
	size_t ms_len;
} ms_aggregate_t;

typedef struct ms_retrieve_aggregation_t {
	long int ms_retval;
	uint32_t ms_smart_meter_id;
} ms_retrieve_aggregation_t;

typedef struct ms_retrieve_decrypted_debug_t {
	uint8_t* ms_retval;
} ms_retrieve_decrypted_debug_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ra_msg2_t* ms_p_msg2;
	sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL enclave_create_session_ocall(void* pms)
{
	ms_create_session_ocall_t* ms = SGX_CAST(ms_create_session_ocall_t*, pms);
	ms->ms_retval = create_session_ocall(ms->ms_sid, ms->ms_dh_msg1, ms->ms_dh_msg1_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_sid, ms->ms_dh_msg2, ms->ms_dh_msg2_size, ms->ms_dh_msg3, ms->ms_dh_msg3_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_close_session_ocall(void* pms)
{
	ms_close_session_ocall_t* ms = SGX_CAST(ms_close_session_ocall_t*, pms);
	ms->ms_retval = close_session_ocall(ms->ms_sid, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_invoke_service_ocall(void* pms)
{
	ms_invoke_service_ocall_t* ms = SGX_CAST(ms_invoke_service_ocall_t*, pms);
	ms->ms_retval = invoke_service_ocall(ms->ms_pse_message_req, ms->ms_pse_message_req_size, ms->ms_pse_message_resp, ms->ms_pse_message_resp_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[9];
} ocall_table_enclave = {
	9,
	{
		(void*)enclave_create_session_ocall,
		(void*)enclave_exchange_report_ocall,
		(void*)enclave_close_session_ocall,
		(void*)enclave_invoke_service_ocall,
		(void*)enclave_sgx_oc_cpuidex,
		(void*)enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t enclave_init_mutex(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, NULL);
	return status;
}

sgx_status_t enclave_ra_init(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* p_gb, size_t len, sgx_ra_context_t* p_ra_context_out, uint32_t smart_meter_id)
{
	sgx_status_t status;
	ms_enclave_ra_init_t ms;
	ms.ms_p_gb = p_gb;
	ms.ms_len = len;
	ms.ms_p_ra_context_out = p_ra_context_out;
	ms.ms_smart_meter_id = smart_meter_id;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_set_g_b(sgx_enclave_id_t eid, sgx_ec256_public_t* p_gb, size_t len)
{
	sgx_status_t status;
	ms_enclave_set_g_b_t ms;
	ms.ms_p_gb = p_gb;
	ms.ms_len = len;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t enclave_retrieve_g_b(sgx_enclave_id_t eid, sgx_ec256_public_t* p_g_b)
{
	sgx_status_t status;
	ms_enclave_retrieve_g_b_t ms;
	ms.ms_p_g_b = p_g_b;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t enclave_verify_sign_gb_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_signature_t* p_sign_gb_ga, size_t len, uint8_t* p_gb_ga, size_t len_gb_ga, uint32_t sm_id)
{
	sgx_status_t status;
	ms_enclave_verify_sign_gb_ga_t ms;
	ms.ms_p_sign_gb_ga = p_sign_gb_ga;
	ms.ms_len = len;
	ms.ms_p_gb_ga = p_gb_ga;
	ms.ms_len_gb_ga = len_gb_ga;
	ms.ms_sm_id = sm_id;
	status = sgx_ecall(eid, 4, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_get_sk_key(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_key_128_t* p_sk_key, uint32_t sm_id)
{
	sgx_status_t status;
	ms_enclave_get_sk_key_t ms;
	ms.ms_p_sk_key = p_sk_key;
	ms.ms_sm_id = sm_id;
	status = sgx_ecall(eid, 5, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_destroy_mutex(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 6, &ocall_table_enclave, NULL);
	return status;
}

sgx_status_t init_aggregator(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 7, &ocall_table_enclave, NULL);
	return status;
}

sgx_status_t aggregate(sgx_enclave_id_t eid, char* payload, size_t len)
{
	sgx_status_t status;
	ms_aggregate_t ms;
	ms.ms_payload = payload;
	ms.ms_len = len;
	status = sgx_ecall(eid, 8, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t retrieve_aggregation(sgx_enclave_id_t eid, long int* retval, uint32_t smart_meter_id)
{
	sgx_status_t status;
	ms_retrieve_aggregation_t ms;
	ms.ms_smart_meter_id = smart_meter_id;
	status = sgx_ecall(eid, 9, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t retrieve_decrypted_debug(sgx_enclave_id_t eid, uint8_t** retval)
{
	sgx_status_t status;
	ms_retrieve_decrypted_debug_t ms;
	status = sgx_ecall(eid, 10, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 11, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce)
{
	sgx_status_t status;
	ms_sgx_ra_proc_msg2_trusted_t ms;
	ms.ms_context = context;
	ms.ms_p_msg2 = (sgx_ra_msg2_t*)p_msg2;
	ms.ms_p_qe_target = (sgx_target_info_t*)p_qe_target;
	ms.ms_p_report = p_report;
	ms.ms_p_nonce = p_nonce;
	status = sgx_ecall(eid, 12, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size)
{
	sgx_status_t status;
	ms_sgx_ra_get_msg3_trusted_t ms;
	ms.ms_context = context;
	ms.ms_quote_size = quote_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_msg3 = p_msg3;
	ms.ms_msg3_size = msg3_size;
	status = sgx_ecall(eid, 13, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

