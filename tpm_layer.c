#include <wolftpm/options.h>
//#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <hal/tpm_io.h>
#include <unistd.h>
//#include <fcntl.h>
#include <poll.h>


int untrusted_poll(int *retval, struct pollfd *fds, nfds_t nfds, int timeout, size_t bytes);

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
	int retval;
	size_t bytes = nfds * sizeof(struct pollfd);
	untrusted_poll(&retval, fds, nfds, timeout, bytes);
	return retval;
}
//#include "tpm_layer.h"

int usleep(useconds_t usec) {
	return 0;
}

int untrusted_open(int *retval, const char *pathname, int flags);

int open(const char *pathname, int flags, ...) {
	int retval;
	untrusted_open(&retval, pathname, flags);
	return retval;
}

int untrusted_close(int *retval, int fd);

int close(int fd) {
	int retval;
	untrusted_close(&retval, fd);
	return retval;
}

ssize_t untrusted_read(ssize_t *retval, int fd, void *buf, size_t count);

ssize_t read(int fd, void *buf, size_t count) {
	ssize_t retval;
	untrusted_read(&retval, fd, buf, count);
	return retval;
}

ssize_t untrusted_write(ssize_t *retval, int fd, const void *buf, size_t count);

ssize_t write(int fd, const void *buf, size_t count) {
	ssize_t retval;
	untrusted_write(&retval, fd, buf, count);
	return retval;
}

int ocall_print_buffer(const unsigned char* buf, int len);


#define TPM2_DEMO_NVRAM_STORE_INDEX     0x01800402

int attest_tpm(unsigned char *pem_certificate) {

	return 0;
}

static const char gNvAuth[] =         "ThisIsMyNvAuth";

int32_t store_hibe_key(unsigned char *hibe_key, int32_t hibe_key_size, int32_t nv_index, unsigned char *password, int32_t passwd_size) ;

int32_t store_hibe_key(unsigned char *hibe_key, int32_t hibe_key_size, int32_t nv_index, unsigned char *password, int32_t passwd_size) {
    (void)nv_index;
    int32_t rc;
    WOLFTPM2_DEV dev;
    //WOLFTPM2_KEYBLOB keyBlob;
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_HANDLE parent;
    WOLFTPM2_NV nv;
    word32 nvAttributes;
    TPMI_RH_NV_AUTH authHandle = TPM_RH_OWNER; /* or TPM_RH_PLATFORM */
    //const char* filename = "keyblob.bin";
    int paramEncAlg = TPM_ALG_NULL;
    //int partialStore = 0;
    int offset = 0;
    /* Needed for TPM2_AppendPublic */
    //byte pubAreaBuffer[sizeof(TPM2B_PUBLIC)];
    //int pubAreaSize;
    word32 nvIndex = TPM2_DEMO_NVRAM_STORE_INDEX;
    byte* auth = (byte*)gNvAuth;
    word32 authSz = (word32)sizeof(gNvAuth)-1;
    //(void)password; (void)passwd_size;
    //byte* auth = (byte*)password;
    //word32 authSz = (word32)passwd_size;

    word32 nvSize;
    /*
    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
        if (argv[1][0] != '-') {
            filename = argv[1];
        }
    }
    while (argc > 1) {
        if (XSTRNCMP(argv[argc-1], "-nvindex=", XSTRLEN("-nvindex=")) == 0) {
            const char* nvIndexStr = argv[argc-1] + XSTRLEN("-nvindex=");
            nvIndex = (word32)XSTRTOUL(nvIndexStr, NULL, 0);
            if (!(authHandle == TPM_RH_PLATFORM && (
                    nvIndex > TPM_20_PLATFORM_MFG_NV_SPACE &&
                    nvIndex < TPM_20_OWNER_NV_SPACE)) &&
                !(authHandle == TPM_RH_OWNER && (
                    nvIndex > TPM_20_OWNER_NV_SPACE &&
                    nvIndex < TPM_20_TCG_NV_SPACE)))
            {
                fprintf(stderr, "Invalid NV Index %s\n", nvIndexStr);
                fprintf(stderr, "\tPlatform Range: 0x%x -> 0x%x\n",
                    TPM_20_PLATFORM_MFG_NV_SPACE, TPM_20_OWNER_NV_SPACE);
                fprintf(stderr, "\tOwner Range: 0x%x -> 0x%x\n",
                    TPM_20_OWNER_NV_SPACE, TPM_20_TCG_NV_SPACE);
                usage();
                return -1;
            }
        }
        else if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else if (XSTRCMP(argv[argc-1], "-priv") == 0) {
            partialStore = PRIVATE_PART_ONLY;
        }
        else if (XSTRCMP(argv[argc-1], "-pub") == 0) {
            partialStore = PUBLIC_PART_ONLY;
        }
        else if (argv[argc-1][0] == '-') {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    };

    if (paramEncAlg == TPM_ALG_CFB) {
        printf("Parameter Encryption: Enabled. (AES CFB)\n\n");
    }
    else if (paramEncAlg == TPM_ALG_XOR) {
        printf("Parameter Encryption: Enabled. (XOR)\n\n");
    }
    else {
        printf("Parameter Encryption: Not enabled (try -aes or -xor).\n\n");
    }*/

    paramEncAlg = TPM_ALG_CFB;

    XMEMSET(&nv, 0, sizeof(nv));
    //XMEMSET(&keyBlob, 0, sizeof(keyBlob));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&parent, 0, sizeof(parent));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != TPM_RC_SUCCESS) {
        //printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    //return -1;

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start TPM session for parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
                TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        //printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
        //    (word32)tpmSession.handle.hndl);
        /* Set TPM session attributes for parameter encryption */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    //return -1;

    //rc = readKeyBlob(filename, &keyBlob);
    //if (rc != 0) goto exit;

    /* Prepare NV_AUTHWRITE and NV_AUTHREAD attributes necessary for password */
    parent.hndl = authHandle;
    rc = wolfTPM2_GetNvAttributesTemplate(parent.hndl, &nvAttributes);
    if (rc != 0) goto exit;
    //printf("After GetNvAttributesTemplate\n");
    //return -1;

    /* Estimate size of NV */
    nvSize = hibe_key_size + sizeof(hibe_key_size);
        //keyBlob.pub.size + sizeof(keyBlob.pub.size) + sizeof(UINT16) +
        //keyBlob.priv.size + sizeof(keyBlob.priv.size) + sizeof(UINT16);
    
    ocall_print_buffer("[store_hibe_key] Before NVOpen\n", 31);

    /* Try and open existing NV */
    rc = wolfTPM2_NVOpen(&dev, &nv, nvIndex, auth, authSz);

    //return -1;
    //ocall_print_buffer("[store_hibe_key] After NVOpen\n", 30);
    //
    ocall_print_buffer("[store_hibe_key] Before NVOpen\n", 31);

    //printf("After NVOpen\n");
    if (rc != 0) {
        /* In not found try create using wolfTPM2 wrapper for NV_Define */
        rc = wolfTPM2_NVCreateAuth(&dev, &parent, &nv, nvIndex,
            nvAttributes, nvSize, auth, authSz);

        if (rc != 0 && rc != TPM_RC_NV_DEFINED) goto exit;
    }
    ocall_print_buffer("[store_hibe_key] After NVOpen\n", 30);

    /* The set auth is done already in NVOpen and NVCreateAuth, but shown here
     * as example for how to set the authentication on a handle */
    wolfTPM2_SetAuthHandle(&dev, 0, &nv.handle);
    //return -1;
    //printf("Storing key at TPM NV index 0x%x with password protection\n\n",
    //         nvIndex);

    //printf("Public part = %hu bytes\n", keyBlob.pub.size);
    rc = wolfTPM2_NVWriteAuth(&dev, &nv, nvIndex,
            (byte*)&hibe_key_size, sizeof(hibe_key_size), 0);
    if (rc != 0) goto exit;
    //printf("Stored 4-byte size marker before the private part\n");
    offset += sizeof(hibe_key_size);

    ocall_print_buffer("[store_hibe_key] After NVWriteAuth\n", 30);

        /* Necessary for storing the publicArea with the correct byte encoding */
    //rc = TPM2_AppendPublic(pubAreaBuffer, (word32)sizeof(pubAreaBuffer),
    //        &pubAreaSize, &keyBlob.pub);
        /* Note:
         * Public Area is the only part of a TPM key that can be stored encoded
         * Private Area is stored as-is, because TPM2B_PRIVATE is byte buffer
         * and UINT16 size field, while Public Area is a complex TCG structure.
         */
    //if (rc != TPM_RC_SUCCESS) {
    //    printf("Encoding of the publicArea failed. Unable to store.\n");
    //    goto exit;
    //}

        /* The buffer holds pub.publicArea and also pub.size(UINT16) */
    rc = wolfTPM2_NVWriteAuth(&dev, &nv, nvIndex,
            (byte*)hibe_key, hibe_key_size, offset);
    if (rc != 0) goto exit;

    //printf("NV write of hibe_key succeeded\n\n");
    //offset += sizeof(UINT16) + keyBlob.pub.size;
    /*
    if (partialStore != PUBLIC_PART_ONLY) {
        printf("Private part = %d bytes\n", keyBlob.priv.size);
        rc = wolfTPM2_NVWriteAuth(&dev, &nv, nvIndex,
            (byte*)&keyBlob.priv.size, sizeof(keyBlob.priv.size), offset);
        if (rc != 0) goto exit;
        printf("Stored 2-byte size marker before the private part\n");
        offset += sizeof(keyBlob.priv.size);

        rc = wolfTPM2_NVWriteAuth(&dev, &nv, nvIndex,
            keyBlob.priv.buffer, keyBlob.priv.size, offset);
        if (rc != 0) goto exit;
        printf("NV write of private part succeeded\n\n");
    }*/

exit:

    if (rc == 0) {
	ocall_print_buffer("[store_hibe_key] After NVOpen\n", 30);
        //printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    wolfTPM2_Cleanup(&dev);

    return rc;
}

int load_hibe_key(unsigned char *hibe_key, int *hibe_key_size, unsigned char *password, unsigned long int passwd_size)
{
    (void)password;
    int rc;
    WOLFTPM2_DEV dev;
    //WOLFTPM2_KEY storage;
    WOLFTPM2_KEYBLOB keyBlob;
    WOLFTPM2_SESSION tpmSession; 
    WOLFTPM2_HANDLE parent; 
    WOLFTPM2_NV nv; 
    TPM2B_AUTH auth; 
    word32 readSize;
    word32 actual_hibe_size;
    TPMI_RH_NV_AUTH authHandle = TPM_RH_OWNER;
    int paramEncAlg = TPM_ALG_CFB;
    //int partialRead = 0;
    int offset = 0;
    /* Needed for TPM2_ParsePublic */
    byte hibeAreaBuffer[4096 * 2];
    //int hibeAreaSize;
    word32 nvIndex = TPM2_DEMO_NVRAM_STORE_INDEX;
    
    /*
    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRNCMP(argv[argc-1], "-nvindex=", XSTRLEN("-nvindex=")) == 0) {
            const char* nvIndexStr = argv[argc-1] + XSTRLEN("-nvindex=");
            nvIndex = (word32)XSTRTOUL(nvIndexStr, NULL, 0);
            if (nvIndex < NV_INDEX_FIRST || nvIndex > NV_INDEX_LAST) {
                fprintf(stderr, "Invalid NV Index %s\n", nvIndexStr);
                fprintf(stderr, "\tPlatform Range: 0x%x -> 0x%x\n",
                    TPM_20_PLATFORM_MFG_NV_SPACE, TPM_20_OWNER_NV_SPACE);
                fprintf(stderr, "\tOwner Range: 0x%x -> 0x%x\n",
                    TPM_20_OWNER_NV_SPACE, TPM_20_TCG_NV_SPACE);
                usage();
                return -1;
            }
        }
        else if (XSTRCMP(argv[argc-1], "-endorsement") == 0) {
            authHandle = TPM_RH_ENDORSEMENT;
        }
        else if (XSTRCMP(argv[argc-1], "-platform") == 0) {
            authHandle = TPM_RH_PLATFORM;
        }
        else if (XSTRCMP(argv[argc-1], "-owner") == 0) {
            authHandle = TPM_RH_OWNER;
        }
        else if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else if (XSTRCMP(argv[argc-1], "-priv") == 0) {
            partialRead = PRIVATE_PART_ONLY;
        }
        else if (XSTRCMP(argv[argc-1], "-pub") == 0) {
            partialRead = PUBLIC_PART_ONLY;
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

    printf("NV Read\n");
    printf("\tNV Index: 0x%08x\n", nvIndex);
    printf("\tAuth: %s\n",
        (authHandle == TPM_RH_ENDORSEMENT) ? "Endorsement" :
        (authHandle == TPM_RH_PLATFORM) ? "Platform" : "Owner");
    if (paramEncAlg == TPM_ALG_CFB) {
        printf("\tParameter Encryption: Enabled. (AES CFB)\n\n");
    }
    else if (paramEncAlg == TPM_ALG_XOR) {
        printf("\tParameter Encryption: Enabled. (XOR)\n\n");
    }
    else {
        printf("\tParameter Encryption: Not enabled (try -aes or -xor).\n\n");
    }*/

    //XMEMSET(&keyBlob, 0, sizeof(keyBlob));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&parent, 0, sizeof(parent));
    XMEMSET(&auth, 0, sizeof(auth));
    //XMEMSET(&storage, 0, sizeof(storage));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != TPM_RC_SUCCESS) {
        //printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start TPM session for parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
                TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        //printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
        //    (word32)tpmSession.handle.hndl);
        /* Set TPM session attributes for parameter encryption */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    if (passwd_size > sizeof(auth.buffer)) {
	    return -4004;
    }

    auth.size = sizeof(gNvAuth)-1;
    XMEMCPY(auth.buffer, gNvAuth, auth.size);
    //auth.size = passwd_size;
    //XMEMCPY(auth.buffer, password, auth.size);

    /* Prepare auth for NV Index */
    XMEMSET(&nv, 0, sizeof(nv));
    nv.handle.hndl = nvIndex;
    nv.handle.auth.size = auth.size;
    XMEMCPY(nv.handle.auth.buffer, auth.buffer, auth.size);

    readSize = sizeof(hibe_key_size);
    //printf("Trying to read %d bytes of hibe_key size marker\n", readSize);
    rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex,
            (byte*)&actual_hibe_size, &readSize, 0);
    if (rc != 0) {
	    //printf("Was the hibe_key written? (see nvram/store)\n");
            goto exit;
    }

    //printf("Successfully read public key part from NV\n\n");
    offset += readSize;

    readSize = actual_hibe_size; /* account for TPM2B size marker */
    //printf("Trying to read %d bytes of hibe_key from NV\n", readSize);
    rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex,
            hibeAreaBuffer, &readSize, offset);
    if (rc != 0) goto exit;
    //printf("Successfully read hibe_key from NV\n\n");
    offset += readSize;

    XMEMCPY(hibe_key, hibeAreaBuffer, actual_hibe_size);
    *hibe_key_size = actual_hibe_size;

    /* Necessary for storing the publicArea with the correct encoding */
    //rc = TPM2_ParsePublic(&keyBlob.pub, pubAreaBuffer,
    //        (word32)sizeof(pubAreaBuffer), &pubAreaSize);
    //if (rc != TPM_RC_SUCCESS) {
    //        printf("Decoding of PublicArea failed. Unable to extract correctly.\n");
    //        goto exit;

#ifdef WOLFTPM_DEBUG_VERBOSE
    //    TPM2_PrintPublicArea(&keyBlob.pub);
#endif

    /*if (partialRead != PUBLIC_PART_ONLY) {
        printf("Trying to read size marker of the private key part from NV\n");
        readSize = sizeof(keyBlob.priv.size);
        rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex,
            (byte*)&keyBlob.priv.size, &readSize, offset);
        if (rc != 0) {
            printf("Was a private key part written? (see nvram/store)\n");
            goto exit;
        }
        printf("Successfully read size marker from NV\n\n");
        offset += readSize;

        readSize = keyBlob.priv.size;
        printf("Trying to read %d bytes of private key part from NV\n", readSize);
        rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex,
            (byte*)&keyBlob.priv.buffer, &readSize, offset);
        if (rc != 0) goto exit;
        printf("Successfully read private key part from NV\n\n");
    }*/

    /* auth 0 is owner, no auth */
    wolfTPM2_SetAuthPassword(&dev, 0, NULL);
    wolfTPM2_UnsetAuth(&dev, 1);

    parent.hndl = authHandle;
    rc = wolfTPM2_NVDeleteAuth(&dev, &parent, nvIndex);
    if (rc != 0) goto exit;

    //printf("Extraction of key from NVRAM at index 0x%x succeeded\n",
    //    nvIndex);

    /*if (!partialRead) {
        // get SRK
        rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
        if (rc != 0) goto exit;

        printf("Trying to load the key extracted from NVRAM\n");
        rc = wolfTPM2_LoadKey(&dev, &keyBlob, &storage.handle);
        if (rc != TPM_RC_SUCCESS) {
            printf("wolfTPM2_LoadKey failed\n");
            goto exit;
        }
        printf("Loaded key to 0x%x\n",
            (word32)keyBlob.handle.hndl);
    }*/

exit:

    if (rc != 0) {
        //printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &keyBlob.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    wolfTPM2_Cleanup(&dev);

    return rc;
}



