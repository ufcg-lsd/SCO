#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "sgx_key_exchange.h"
#include "sgx_trts.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, create_session_ocall, (uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, exchange_report_ocall, (uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, close_session_ocall, (uint32_t sid, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, invoke_service_ocall, (uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t enclave_init_mutex(sgx_enclave_id_t eid);
sgx_status_t enclave_ra_init(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* p_gb, size_t len, sgx_ra_context_t* p_ra_context_out, uint32_t smart_meter_id);
sgx_status_t enclave_set_g_b(sgx_enclave_id_t eid, sgx_ec256_public_t* p_gb, size_t len);
sgx_status_t enclave_retrieve_g_b(sgx_enclave_id_t eid, sgx_ec256_public_t* p_g_b);
sgx_status_t enclave_verify_sign_gb_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_signature_t* p_sign_gb_ga, size_t len, uint8_t* p_gb_ga, size_t len_gb_ga, uint32_t sm_id);
sgx_status_t enclave_get_sk_key(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_key_128_t* p_sk_key, uint32_t sm_id);
sgx_status_t enclave_destroy_mutex(sgx_enclave_id_t eid);
sgx_status_t init_aggregator(sgx_enclave_id_t eid);
sgx_status_t aggregate(sgx_enclave_id_t eid, char* payload, size_t len);
sgx_status_t retrieve_aggregation(sgx_enclave_id_t eid, long int* retval, uint32_t smart_meter_id);
sgx_status_t retrieve_decrypted_debug(sgx_enclave_id_t eid, uint8_t** retval);
sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
