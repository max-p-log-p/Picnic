#include "pqtr.h"

int
pqtr_sign(picnic_privatekey_t *sks, picnic_publickey_t *pks, const uint8_t *message, size_t message_len,
                uint8_t *signature, size_t *signature_len)
{
	return EXIT_SUCCESS;
}

int
pqtr_verify(picnic_publickey_t *pks, const uint8_t *message, size_t message_len,
                  const uint8_t *signature, size_t signature_len)
{
	return EXIT_SUCCESS;
}

int
read_file(char *fmt, char *prefix, int index, uint8_t *buf, size_t buflen)
{
	FILE *f;
	char *pathname;

	asprintf(&pathname, fmt, prefix, index);

	f = fopen(pathname, "w");

	fread(buf, sizeof(buf[0]), buflen, f);

	fclose(f);
	free(pathname);
}

int
write_file(char *fmt, char *prefix, int index, uint8_t *buf, size_t buflen)
{
	FILE *f;
	char *pathname;

	asprintf(&pathname, fmt, prefix, index);

	f = fopen(pathname, "w");

	fwrite(buf, sizeof(buf[0]), buflen, f);

	fclose(f);
	free(pathname);
}

int
main(int argc, char *argv[])
{
	uint8_t *buf, *sigBytes;
	char *prefix, *msg;
	int alg, bytesRequired, opt, ret, ringSize, threshold;
	size_t buflen, sigBytesLen;
	signature_t *sig;

	ret = 0;
	ringSize = threshold = 1;
    paramset_t paramset;
	picnic_params_t parameters = Picnic_L5_UR;
	picnic_publickey_t *pks;
	picnic_privatekey_t *sks;

	while ((opt = getopt(argc, argv, "km:n:p:st:v")) != -1) {
		switch (opt) {
		case 'k':
			alg = KEY_GEN;
			break;
		case 'n':
			ringSize = strtol(optarg, NULL, 10);
			break;
		case 'm':
			msg = optarg;
			break;
		case 'p':
			prefix = optarg;
			break;
		case 's':
			alg = SIGN;
			break;
		case 't':
			threshold = strtol(optarg, NULL, 10);
			break;
		case 'v':
			alg = VERIFY;
			break;
		default:
			fprintf(stderr, "usage: %s\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (prefix == NULL) {
		fprintf(stderr, "no prefix\n");
		exit(EXIT_FAILURE);
	}


	get_param_set(parameters, &paramset);
	buflen = 1 + 3 * paramset.stateSizeBytes;
	buf = malloc(buflen);

	pks = calloc(ringSize, sizeof(*pks));
	sks = calloc(threshold, sizeof(*sks));

	switch (alg) {
	case KEY_GEN:
			for (int i = 0; i < ringSize; ++i) {
				picnic_keygen(parameters, &pks[i], &sks[i]);

				bytesRequired = picnic_write_public_key(&pks[i], buf, buflen);
				write_file("%s_pk_%d", prefix, i, buf, bytesRequired);

				bytesRequired = picnic_write_private_key(&sks[i], buf, buflen);
				write_file("%s_sk_%d", prefix, i, buf, bytesRequired);
			}
			break;
	case SIGN:
			for (int i = 0; i < threshold; ++i) {
				read_file("%s_sk_%d", prefix, i, buf, buflen);
				picnic_read_private_key(&sks[i], buf, buflen);
			}

			for (int i = 0; i < ringSize; ++i) {
				read_file("%s_pk_%d", prefix, i, buf, buflen);
				picnic_read_public_key(&pks[i], buf, buflen);
			}

			pqtr_sign(sks, pks, msg, strlen(msg), sigBytes, &sigBytesLen);
			write_file("%s_%d", "sign", 0, sigBytes, sigBytesLen);
			break;
	case VERIFY:
			for (int i = 0; i < ringSize; ++i) {
				read_file("%s_pk_%d", prefix, i, buf, buflen);
				picnic_read_public_key(&pks[i], buf, buflen);
			}

			ret = pqtr_verify(pks, msg, strlen(msg), sigBytes, sigBytesLen);
			break;
	default:
			fprintf(stderr, "bad alg\n");
			break;
	}

	free(buf);
	return ret;
}
