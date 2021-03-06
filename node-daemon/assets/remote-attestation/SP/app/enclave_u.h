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

void SGX_UBRIDGE(SGX_NOCONVENTION, emit_debug, (const char* str));
void SGX_UBRIDGE(SGX_NOCONVENTION, print_byte_array, (void* mem, size_t len));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, create_session_ocall, (uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, exchange_report_ocall, (uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, close_session_ocall, (uint32_t sid, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, invoke_service_ocall, (uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t enclave_ra_init(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* p_gb_out);
sgx_status_t enclave_set_ga(sgx_enclave_id_t eid, sgx_ec256_public_t* p_ga_in, size_t len);
sgx_status_t enclave_derive_keys(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t enclave_get_gb(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* p_gb_out);
sgx_status_t enclave_get_sign_gb_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_signature_t* p_sign_gb_ga);
sgx_status_t enclave_compute_msg2_mac(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* p_src, size_t len, sgx_cmac_128bit_key_t* p_mac_out);
sgx_status_t enclave_encrypt(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* data, size_t data_len, uint8_t* buffer, size_t buffer_len);
sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
