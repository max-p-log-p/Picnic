#include "pqtr.h"

int
pqtr_sign(picnic_privatekey_t* sk, const uint8_t* message, size_t message_len,
                uint8_t* signature, size_t* signature_len)
{
	return EXIT_SUCCESS;
}

int
pqtr_verify(picnic_publickey_t* pk, const uint8_t* message, size_t message_len,
                  const uint8_t* signature, size_t signature_len)
{
	return EXIT_SUCCESS;
}

int
write_key(char *fmt, char *prefix, uint8_t *buf, size_t buflen)
{
	FILE *f;
	char *pathname;

	asprintf(&pathname, fmt, prefix);

	f = fopen(pathname, "w");

	fwrite(buf, sizeof(buf[0]), buflen, f);

	fclose(f);
	free(pathname);
}

int
main(int argc, char *argv[])
{
	uint8_t *buf;
	int bytesRequired, opt;

    paramset_t paramset;
	picnic_params_t parameters = Picnic_L5_UR;
	picnic_publickey_t pk;
	picnic_privatekey_t sk;

	while ((opt = getopt(argc, argv, "k:sv")) != -1) {
		switch (opt) {
		case 'k':
			get_param_set(parameters, &paramset);
			size_t buflen = 1 + 3 * paramset.stateSizeBytes;

			buf = malloc(buflen);

			picnic_keygen(parameters, &pk, &sk);

			bytesRequired = picnic_write_public_key(&pk, buf, buflen);
			write_key("%s_pk", optarg, buf, bytesRequired);

			bytesRequired = picnic_write_private_key(&sk, buf, buflen);
			write_key("%s_sk", optarg, buf, bytesRequired);

			free(buf);
			return EXIT_SUCCESS;
		case 's':
			/*
			read(fd, buf, bufLen);
			picnic_read_private_key(sk, buf, buflen);
			picnic_read_public_key(pk, buf, buflen);
			pqtr_sign();
			*/
			break;
		case 'v':
			/*
			read(fd, buf, bufLen);
			picnic_read_public_key(pk, buf, buflen);
			pqtr_verify();
			*/
		default:
			fprintf(stderr, "usage: %s\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	return 0;
}
