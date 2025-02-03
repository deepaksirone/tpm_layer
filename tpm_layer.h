#ifndef _TPM_LAYER_H_
#define _TPM_LAYER_H_

extern "C" int attest_tpm(unsigned char *pem_certificate);
extern "C" int32_t store_hibe_key(unsigned char *hibe_key, int32_t hibe_key_size, int32_t nv_index, unsigned char *password, int32_t passwd_size);
extern "C" int load_hibe_key(unsigned char *hibe_key, int *hibe_key_size, unsigned char *password, unsigned long int passwd_size);
extern "C" int untrusted_open(const char *path, int flags);
extern "C" int untrusted_close(int fd);

#endif
