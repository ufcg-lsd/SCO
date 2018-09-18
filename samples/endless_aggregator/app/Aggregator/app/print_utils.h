#ifndef _PRINT_UTILS_H
#define _PRINT_UTILS_H

#include "string.h"
#include "stdint.h"
#include "stdio.h"
#include "sgx_error.h"

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

static sgx_errlist_t sgx_errlist[] =
{
    {   
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },  
    {   
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },  
    {   
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },  
    {   
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },  
    {   
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },  
    {   
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },  
    {   
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },  
    {   
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },  
    {   
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },  
    {   
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },  
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++)
    {   
        if(ret == sgx_errlist[idx].err)
        {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }   

    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
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

#endif
