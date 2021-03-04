#include <assert.h>
#include <bearssl.h>
#include <errno.h>
#include <gmni/certs.h>
#include <gmni/gmni.h>
#include <stdio.h>
#include <stdlib.h>

static void
crt_append(void *ctx, const void *src, size_t len)
{
	br_x509_certificate *crt = (br_x509_certificate *)ctx;
	crt->data = realloc(crt->data, crt->data_len + len);
	assert(crt->data);
	memcpy(&crt->data[crt->data_len], src, len);
	crt->data_len += len;
}

static void
key_append(void *ctx, const void *src, size_t len)
{
	br_skey_decoder_context *skctx = (br_skey_decoder_context *)ctx;
	br_skey_decoder_push(skctx, src, len);
}

int
gmni_ccert_load(struct gmni_client_certificate *cert, FILE *certin, FILE *skin)
{
	// TODO: Better error propagation to caller
	static unsigned char buf[BUFSIZ];

	br_pem_decoder_context pemdec;
	br_pem_decoder_init(&pemdec);

	cert->chain = NULL;
	cert->nchain = 0;

	static const char *certname = "CERTIFICATE";
	while (!feof(certin)) {
		size_t n = fread(&buf, 1, sizeof(buf), certin);
		if (ferror(certin)) {
			goto error;
		}
		size_t q = 0;
		while (q < n) {
			q += br_pem_decoder_push(&pemdec, &buf[q], n - q);
			switch (br_pem_decoder_event(&pemdec)) {
			case BR_PEM_BEGIN_OBJ:
				if (strcmp(br_pem_decoder_name(&pemdec), certname) != 0) {
					break;
				}
				cert->chain = realloc(cert->chain,
					sizeof(br_x509_certificate) * (cert->nchain + 1));
				memset(&cert->chain[cert->nchain], 0, sizeof(*cert->chain));
				br_pem_decoder_setdest(&pemdec, &crt_append,
						&cert->chain[cert->nchain]);
				++cert->nchain;
				break;
			case BR_PEM_END_OBJ:
				break;
			case BR_PEM_ERROR:
				fprintf(stderr, "Error decoding PEM certificate\n");
				errno = EINVAL;
				goto error;
			}
		}
	}

	if (cert->nchain == 0) {
		fprintf(stderr, "No certificates found in provided client certificate file\n");
		errno = EINVAL;
		goto error;
	}

	br_skey_decoder_context skdec = {0};
	br_skey_decoder_init(&skdec);
	br_pem_decoder_init(&pemdec);

	// TODO: Better validation of PEM file
	while (!feof(skin)) {
		size_t n = fread(&buf, 1, sizeof(buf), skin);
		if (ferror(skin)) {
			goto error;
		}
		size_t q = 0;
		while (q < n) {
			q += br_pem_decoder_push(&pemdec, &buf[q], n - q);
			switch (br_pem_decoder_event(&pemdec)) {
			case BR_PEM_BEGIN_OBJ:
				br_pem_decoder_setdest(&pemdec, &key_append, &skdec);
				break;
			case BR_PEM_END_OBJ:
				// no-op
				break;
			case BR_PEM_ERROR:
				fprintf(stderr, "Error decoding PEM private key\n");
				errno = EINVAL;
				goto error;
			}
		}
	}

	int err = br_skey_decoder_last_error(&skdec);
	if (err != 0) {
		fprintf(stderr, "Error loading private key: %d\n", err);
		errno = EINVAL;
		goto error;
	}
	switch (br_skey_decoder_key_type(&skdec)) {
		struct gmni_private_key *k;
		const br_ec_private_key *ec;
		const br_rsa_private_key *rsa;
	case BR_KEYTYPE_RSA:
		rsa = br_skey_decoder_get_rsa(&skdec);
		cert->key = k = malloc(sizeof(*k)
				+ rsa->plen + rsa->qlen
				+ rsa->dplen + rsa->dqlen
				+ rsa->iqlen);
		assert(k);
		k->type = BR_KEYTYPE_RSA;
		k->rsa = *rsa;
		k->rsa.p = k->data;
		k->rsa.q = k->rsa.p + k->rsa.plen;
		k->rsa.dp = k->rsa.q + k->rsa.qlen;
		k->rsa.dq = k->rsa.dp + k->rsa.dplen;
		k->rsa.iq = k->rsa.dq + k->rsa.dqlen;
		memcpy(k->rsa.p, rsa->p, rsa->plen);
		memcpy(k->rsa.q, rsa->q, rsa->qlen);
		memcpy(k->rsa.dp, rsa->dp, rsa->dplen);
		memcpy(k->rsa.dq, rsa->dq, rsa->dqlen);
		memcpy(k->rsa.iq, rsa->iq, rsa->iqlen);
		break;
	case BR_KEYTYPE_EC:
		ec = br_skey_decoder_get_ec(&skdec);
		cert->key = k = malloc(sizeof(*k) + ec->xlen);
		assert(k);
		k->type = BR_KEYTYPE_EC;
		k->ec.curve = ec->curve;
		k->ec.x = k->data;
		k->ec.xlen = ec->xlen;
		memcpy(k->ec.x, ec->x, ec->xlen);
		break;
	default:
		assert(0);
	}

	fclose(certin);
	fclose(skin);
	return 0;

error:
	fclose(certin);
	fclose(skin);
	free(cert->chain);
	return 1;
}
