#ifndef GEMINI_CERTS_H
#define GEMINI_CERTS_H
#include <bearssl.h>
#include <stdio.h>

struct gmni_options;

struct gmni_client_certificate {
	br_x509_certificate *chain;
	size_t nchain;
	struct gmni_private_key *key;
};

struct gmni_private_key {
	int type;
	union {
		br_rsa_private_key rsa;
		br_ec_private_key ec;
	};
	unsigned char data[];
};

// Returns nonzero on failure and sets errno
int gmni_ccert_load(struct gmni_client_certificate *cert,
		FILE *certin, FILE *skin);

#endif
