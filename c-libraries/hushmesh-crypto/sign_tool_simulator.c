#ifndef ENCLAVE_BUILD

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hm_log.h"

typedef struct _xml_parameter_t
{
    const char* name;       //the element name
    uint64_t max_value;  
    uint64_t min_value;
    uint64_t value;         //parameter value. Initialized with the default value.
    uint32_t flag;          //Show whether it has been matched
} xml_parameter_t;

#define TCS_NUM_MIN 0
#define TCS_POLICY_BIND 0
#define TCS_POLICY_UNBIND 0
#define STACK_SIZE_MIN 0
#define STACK_SIZE_MAX 0
#define HEAP_SIZE_MIN 0
#define HEAP_SIZE_MAX 0
#define RSRV_SIZE_MIN 0
#define RSRV_SIZE_MAX 0
#define DEFAULT_MISC_SELECT 0
#define DEFAULT_MISC_MASK 0
#define USER_REGION_SIZE 0
#define ENCLAVE_MAX_SIZE_64 0
#define ISVFAMILYID_MAX 0
#define ISVEXTPRODID_MAX 0
#define FEATURE_LOADER_SELECTS 0
#define FEATURE_MUST_BE_DISABLED 0

int sgx_enclave_sign(const unsigned char *input_enclave_buf, size_t input_enclave_len,
		const unsigned char *private_key_der, size_t private_key_len,
		const uint64_t *parameter_buf, size_t parameter_len,
		const uint32_t *flags_buf, size_t flags_len,
		unsigned char *output_enclave_buf, size_t output_enclave_len,
		unsigned char *output_enclave_hash_buf, size_t output_enclave_hash_len,
		const int64_t unix_timestamp)
{
    xml_parameter_t parameter[] = {/* name,                 max_value          min_value,      default value,       flag */
                                   {"ProdID",               0xFFFF,                0,              0,                   0},
                                   {"ISVSVN",               0xFFFF,                0,              0,                   0},
                                   {"ReleaseType",          1,                     0,              0,                   0},
                                   {"IntelSigned",          1,                     0,              0,                   0},
                                   {"ProvisionKey",         1,                     0,              0,                   0},
                                   {"LaunchKey",            1,                     0,              0,                   0},
                                   {"DisableDebug",         1,                     0,              0,                   0},
                                   {"HW",                   0x10,                  0,              0,                   0},
                                   {"TCSNum",               0xFFFFFFFF,            TCS_NUM_MIN,    TCS_NUM_MIN,         0},
                                   {"TCSMaxNum",            0xFFFFFFFF,            TCS_NUM_MIN,    TCS_NUM_MIN,         0},
                                   {"TCSMinPool",           0xFFFFFFFF,            0,              TCS_NUM_MIN,         0},
                                   {"TCSPolicy",            TCS_POLICY_UNBIND,     TCS_POLICY_BIND,TCS_POLICY_UNBIND,   0},
                                   {"StackMaxSize",         ENCLAVE_MAX_SIZE_64/2, STACK_SIZE_MIN, STACK_SIZE_MAX,      0},
                                   {"StackMinSize",         ENCLAVE_MAX_SIZE_64/2, STACK_SIZE_MIN, STACK_SIZE_MIN,      0},
                                   {"HeapMaxSize",          ENCLAVE_MAX_SIZE_64/2, 0,              HEAP_SIZE_MAX,       0},
                                   {"HeapMinSize",          ENCLAVE_MAX_SIZE_64/2, 0,              HEAP_SIZE_MIN,       0},
                                   {"HeapInitSize",         ENCLAVE_MAX_SIZE_64/2, 0,              HEAP_SIZE_MIN,       0},
                                   {"ReservedMemMaxSize",   ENCLAVE_MAX_SIZE_64/2, 0,              RSRV_SIZE_MAX,       0},
                                   {"ReservedMemMinSize",   ENCLAVE_MAX_SIZE_64/2, 0,              RSRV_SIZE_MIN,       0},
                                   {"ReservedMemInitSize",  ENCLAVE_MAX_SIZE_64/2, 0,              RSRV_SIZE_MIN,       0},
                                   {"ReservedMemExecutable",1,                     0,              0,                   0},
                                   {"MiscSelect",           0x00FFFFFFFF,          0,              DEFAULT_MISC_SELECT, 0},
                                   {"MiscMask",             0x00FFFFFFFF,          0,              DEFAULT_MISC_MASK,   0},
                                   {"EnableKSS",            1,                     0,              0,                   0},
                                   {"ISVFAMILYID_H",        ISVFAMILYID_MAX,       0,              0,                   0},
                                   {"ISVFAMILYID_L",        ISVFAMILYID_MAX ,      0,              0,                   0},
                                   {"ISVEXTPRODID_H",       ISVEXTPRODID_MAX,      0,              0,                   0},
                                   {"ISVEXTPRODID_L",       ISVEXTPRODID_MAX,      0,              0,                   0},
                                   {"EnclaveImageAddress",  0xFFFFFFFFFFFFFFFF,    0x1000,         0,                   0},
                                   {"ELRangeStartAddress",  0xFFFFFFFFFFFFFFFF,    0,              0,                   0},
                                   {"ELRangeSize",          0xFFFFFFFFFFFFFFFF,    0x1000,         0,                   0},
                                   {"PKRU",                 FEATURE_LOADER_SELECTS,                     FEATURE_MUST_BE_DISABLED,              FEATURE_MUST_BE_DISABLED,                   0},
                                   {"AMX",                  FEATURE_LOADER_SELECTS,                     FEATURE_MUST_BE_DISABLED,              FEATURE_MUST_BE_DISABLED,                   0},
                                   {"UserRegionSize",       ENCLAVE_MAX_SIZE_64/2, 0,              USER_REGION_SIZE,    0}};

    size_t parameter_count = sizeof(parameter)/sizeof(parameter[0]);
    if(input_enclave_buf == NULL || input_enclave_len == 0 ||
            private_key_der == NULL || private_key_len == 0 ||
            parameter_buf == NULL || parameter_len == 0 ||
            flags_buf == NULL || flags_len == 0 ||
            output_enclave_buf == NULL || output_enclave_len == 0 ||
            output_enclave_hash_buf == NULL || output_enclave_hash_len == 0 ||
            unix_timestamp <= 0) {
        return -1;
    }
    if(input_enclave_len != output_enclave_len) {
        return -1;
    }
    if(output_enclave_hash_len != 32) {
        return -1;
    }
    if(parameter_len != (parameter_count * sizeof(uint64_t))) {
        return -1;
    }
    if(flags_len != (parameter_count * sizeof(uint32_t))) {
        return -1;
    }
    hml_info("Simulator mode skipping SGX enclave signing");
    memcpy(output_enclave_buf, input_enclave_buf, input_enclave_len);
    return 0;
}

#endif