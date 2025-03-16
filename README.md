## TPM Layer for SGX Enclaves

Wrapper code for the wolfTPM API to store HIBE keys into the TPM from an SGX enclave.

### Requirements

* `libwolfssl.a`: wolfSSL configured with `./configure --prefix=$(pwd)/build --enable-aescfb --enable-aesni`
* `libwolftpm.a`: Configured with `./configure --with-pic=yes --enable-wolfcrypt --enable-static --enable-devtpm --with-wolfcrypt=<path_to_wolfssl_lib_install> --prefix=$(pwd)/build`
* Definitions of the following OCalls in the Enclave/unstrusted app:
``` 
untrusted {
    	void ocall_print_buffer([in] const unsigned char *buf, int len);
        int untrusted_open([in, string] const char *path, int flags);
        int untrusted_poll([in, out, size = bytes] struct pollfd *fds, nfds_t nfds, int timeout, size_t bytes);
        ssize_t untrusted_read(int fd, [out, size = count] void *buf, size_t count);
        int untrusted_close(int fd);
        ssize_t untrusted_write(int fd, [in, size = count] const void *buf, size_t count);
};
```


