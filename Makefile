
WOLFTPM_STATIC_LIB_PATH ?= /home/bug/wolfTPM/build/lib
WOLFTPM_INCLUDE_PATH ?= /home/bug/wolfTPM/build/include
WOLFSSL_INCLUDE_PATH ?= /home/bug/wolfSSL/build/include

.PHONY: all
all: tpm_layer.c tpm_layer.h
	gcc -nostdlib -static -fPIE -I$(WOLFSSL_INCLUDE_PATH) -I$(WOLFTPM_INCLUDE_PATH) -L$(WOLFTPM_STATIC_LIB_PATH) tpm_layer.c -c -o tpm_layer.o
	cp $(WOLFTPM_STATIC_LIB_PATH)/libwolftpm.a .
	ar rcs libwolftpm.a tpm_layer.o


.PHONY: clean
clean:
	rm *.o *.a


