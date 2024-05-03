#include "pqtr.h"

static inline size_t
getPkSize(paramset_t *commit_params)
{
	return 1 + 2 * commit_params->stateSizeBytes;
}

static inline size_t
getSkSize(paramset_t *commit_params)
{
	return 1 + 3 * commit_params->stateSizeBytes;
}

static inline size_t
getCommitsSize(paramset_t *params)
{
	return params->digestSizeBytes;
}

static inline size_t
getGcommitsSize(paramset_t *params)
{
	return params->UnruhGWithInputBytes;
}

static inline size_t
getOpenSize(paramset_t *params)
{
	return 2 * params->seedSizeBytes + params->stateSizeBytes + params->andSizeBytes;
}

static inline size_t
getEncSize(pqtr_params_t *params, paramset_t *commit_params)
{
	return params->ringSize * sizeof(field_t) + getOpenSize(commit_params) + params->keySize;
}

static inline size_t
getSigSize(paramset_t *params)
{
	return params->numMPCRounds * (getCommitsSize(params) + getGcommitsSize(params) + getOpenSize(params));
}

static inline size_t
getProofSize(pqtr_params_t *params, paramset_t *commit_params)
{
	return params->ringSize * (sizeof(field_t) + getSigSize(commit_params)) + params->keySize + params->numOpenings * getEncSize(params, commit_params);
}

void H(const char *message, size_t messageLen, signature_t *trap_sigs, signature_t *sigs, field_t *output, pqtr_params_t *pqtr_params, paramset_t *params, int counter)
{
    HashInstance ctx;

    /* Hash the inputs with prefix, store digest in output */
    HashInit(&ctx, params, HASH_PREFIX_6);
	HashUpdate(&ctx, (uint8_t *)message, messageLen);
	HashUpdate(&ctx, (uint8_t *)&counter, sizeof(counter));

	for (int i = 0; i < pqtr_params->threshold; ++i) {
		for (int r = 0; r < params->numMPCRounds; ++r) {
			HashUpdate(&ctx, trap_sigs[i].proofs[r].view3Commitment, getCommitsSize(params));
			HashUpdate(&ctx, trap_sigs[i].proofs[r].view3UnruhG, getGcommitsSize(params));
		}
	}

	for (int i = 0; i < pqtr_params->ringSize - pqtr_params->threshold; ++i) {
		for (int r = 0; r < params->numMPCRounds; ++r) {
			HashUpdate(&ctx, sigs[i].proofs[r].view3Commitment, getCommitsSize(params));
			HashUpdate(&ctx, sigs[i].proofs[r].view3UnruhG, getGcommitsSize(params));
		}
	}

    HashFinal(&ctx);
    HashSqueeze(&ctx, (uint8_t *)output, sizeof(*output));
}

void H1(const char *message, size_t messageLen, field_t *points, signature_t *sigs, uint8_t *enc, uint8_t *output, paramset_t *commit_params, pqtr_params_t *params)
{
    HashInstance ctx;

    /* Hash the inputs with prefix, store digest in output */
    HashInit(&ctx, commit_params, HASH_PREFIX_9);
	HashUpdate(&ctx, (uint8_t *)message, messageLen);

	for (int i = 0; i < params->ringSize - params->threshold; ++i) {
		HashUpdate(&ctx, (uint8_t *)&points[i], sizeof(*points));
		for (int r = 0; r < commit_params->numMPCRounds; ++r) {
			HashUpdate(&ctx, sigs[i].proofs[r].view3Commitment, getCommitsSize(commit_params));
			HashUpdate(&ctx, sigs[i].proofs[r].view3UnruhG, getGcommitsSize(commit_params));
		}
	}

	for (int o = 0; o < params->numOpenings; ++o)
		HashUpdate(&ctx, &enc[o], getEncSize(params, commit_params));

    HashFinal(&ctx);
    HashSqueeze(&ctx, output, sizeof(*output));
}

void permute(field_t *trap_points, field_t *points, signature_t *trap_sigs, signature_t *sigs, uint8_t *key, size_t keyLen, uint8_t *output, size_t outputLen, paramset_t *params, pqtr_params_t *pqtr_params)
{
    HashInstance ctx;

    /* Hash the key with prefix, store digest in output */
    HashInit(&ctx, params, HASH_PREFIX_8);

	for (int i = 0; i < pqtr_params->threshold; ++i)
		HashUpdate(&ctx, (uint8_t *)&trap_points[i], sizeof(*trap_points));

	for (int i = 0; i < pqtr_params->ringSize - pqtr_params->threshold; ++i)
		HashUpdate(&ctx, (uint8_t *)&points[i], sizeof(*points));

	for (int i = 0; i < pqtr_params->threshold; ++i) {
		for (int r = 0; r < params->numMPCRounds; ++r) {
			HashUpdate(&ctx, trap_sigs[i].proofs[r].seed1, params->seedSizeBytes);
			HashUpdate(&ctx, trap_sigs[i].proofs[r].seed2, params->seedSizeBytes);
			if (trap_sigs[i].challengeBits[r])
				HashUpdate(&ctx, (uint8_t *)trap_sigs[i].proofs[r].inputShare, params->stateSizeBytes);
			HashUpdate(&ctx, trap_sigs[i].proofs[r].communicatedBits, params->andSizeBytes);
		}
	}

	for (int i = 0; i < pqtr_params->ringSize - pqtr_params->threshold; ++i) {
		for (int r = 0; r < params->numMPCRounds; ++r) {
			HashUpdate(&ctx, sigs[i].proofs[r].seed1, params->seedSizeBytes);
			HashUpdate(&ctx, sigs[i].proofs[r].seed2, params->seedSizeBytes);
			if (sigs[i].challengeBits[r])
				HashUpdate(&ctx, (uint8_t *)sigs[i].proofs[r].inputShare, params->stateSizeBytes);
			HashUpdate(&ctx, sigs[i].proofs[r].communicatedBits, params->andSizeBytes);
		}
	}

    HashUpdate(&ctx, key, keyLen);
    HashFinal(&ctx);
    HashSqueeze(&ctx, output, outputLen);
}

void
interpolate(field_t *poly, field_t output, field_t *trap_outputs, field_t *outputs, int i1, int i2)
{
}

field_t
eval_poly(field_t *poly, int len, field_t input)
{
	field_t sum = 0;

	for (int i = len - 1; i >= 0; --i)
		sum = poly[i] + input * sum;

	return sum;
}

int
degree(field_t *poly, int len)
{
	int i;

	for (i = len - 1; i > 0; --i)
		if (poly[i])
			break;

	return i;
}

void
trap_open(field_t test, field_t *trap_outputs, field_t *outputs, trap_commit_t *commits, signature_t *trap_sigs, paramset_t *commit_params, pqtr_params_t *params)
{
	field_t point, *poly;
	// field_t *poly2;

	poly = calloc(params->ringSize - params->threshold + 1, sizeof(*poly));
	// poly2 = calloc(params->ringSize + 1, sizeof(*poly2));

	interpolate(poly, test, trap_outputs, outputs, params->threshold, params->ringSize);

	for (int i = 0; i < params->threshold; ++i) {
		point = eval_poly(poly, params->ringSize - params->threshold + 1, i + 1);
		trapdoor_open((uint8_t *)&point, sizeof(point), commits[i].views, commits[i].seeds, commits[i].as, commits[i].gs, &trap_sigs[i], commit_params);
	}

	// interpolate(poly2, test, outputs, 0, params->ringSize);
	// assert(degree(poly2, params->ringSize + 1) <= params->ringSize - params->threshold);

	free(poly);
	// free(poly2);
}

void
addProof(uint8_t **sig, size_t *signature_len, field_t *trap_points, field_t *points, signature_t *trap_sigs, signature_t *sigs, uint8_t *key, uint8_t *enc, pqtr_params_t *params, paramset_t *commit_params)
{
	memcpy(*sig, trap_points, params->threshold * sizeof(field_t));
	*sig += params->threshold * sizeof(field_t);

	memcpy(*sig, points, (params->ringSize - params->threshold) * sizeof(field_t));
	*sig += (params->ringSize - params->threshold) * sizeof(field_t);

	for (int i = 0; i < params->threshold; ++i) {
		serializeSignature(&trap_sigs[i], *sig, getSigSize(commit_params), commit_params);
		*sig += getSigSize(commit_params);
	}

	for (int i = 0; i < params->ringSize - params->threshold; ++i) {
		serializeSignature(&sigs[i], *sig, getSigSize(commit_params), commit_params);
		*sig += getSigSize(commit_params);
	}

	memcpy(*sig, key, params->keySize);
	*sig += params->keySize;

	memcpy(*sig, enc, params->numOpenings * getEncSize(params, commit_params));
	*sig += getEncSize(params, commit_params);
}

void
pqtr_sign(picnic_privatekey_t *sks, picnic_publickey_t *pks, pqtr_params_t *params,
		paramset_t *commit_params, const char *message, size_t message_len,
		uint8_t **signature, size_t *signature_len)
{
	signature_t *sigs, **trap_sigs;
	field_t *points, **trap_points;
	field_t *tests;
	trap_commit_t *commits;
	uint8_t *enc, *keys, *sig;
	uint8_t open;
	size_t encSize;

	encSize = getEncSize(params, commit_params);

	commits = calloc(params->ringSize, sizeof(*commits));
	points = calloc(params->ringSize - params->threshold, sizeof(*points));
	sigs = calloc(params->ringSize - params->threshold, sizeof(*sigs));
	enc = calloc(params->numOpenings, encSize);
	keys = calloc(params->numOpenings, params->keySize);
	tests = calloc(params->numOpenings, sizeof(*tests));
	trap_points = calloc(params->numOpenings, sizeof(*trap_points));
	trap_sigs = calloc(params->numOpenings, sizeof(*trap_sigs));

	for (int i = 0; i < params->threshold; ++i) {
		commits[i].views = allocateViews(commit_params);
		commits[i].seeds = allocateSeeds(commit_params);
		commits[i].as = allocateCommitments(commit_params, 0);
		commits[i].gs = allocateGCommitments(commit_params);
	}

	for (int i = 0; i < params->ringSize - params->threshold; ++i)
		allocateSignature(&sigs[i], commit_params);

	for (int o = 0; o < params->numOpenings; ++o) {
		trap_points[o] = calloc(params->threshold, sizeof(*trap_points));
		trap_sigs[o] = calloc(params->threshold, sizeof(**trap_sigs));

		for (int i = 0; i < params->threshold; ++i)
			allocateSignature(&trap_sigs[o][i], commit_params);
	}

	*signature_len = params->numProofs * getProofSize(params, commit_params);
	sig = *signature = malloc(*signature_len);
	printf("Signature Size: %lu\n", *signature_len);

	for (int p = 0; p < params->numProofs; ++p) {
		getrandom(points, (params->ringSize - params->threshold) * sizeof(*points), 0);

		for (int i = 0; i < params->ringSize - params->threshold; ++i)
			commit(&pks[i + params->threshold], (uint8_t *)&points[i], sizeof(points[i]), &sigs[i], commit_params);

		for (int o = 0; o < params->numOpenings; ++o) {
			for (int i = 0; i < params->threshold; ++i)
				trapdoor_commit((uint32_t *)&sks[i], &pks[i], commits[i].views, commits[i].seeds, commits[i].as, commits[i].gs, &trap_sigs[o][i], commit_params);

			H(message, message_len, trap_sigs[o], sigs, &tests[o], params, commit_params, o);

			trap_open(tests[o], trap_points[o], points, commits, trap_sigs[o], commit_params, params);

			getrandom(keys, params->numOpenings * params->keySize, 0);

			permute(trap_points[o], points, trap_sigs[o], sigs, &keys[o], params->keySize, &enc[o], encSize, commit_params, params);
		}

		H1(message, message_len, points, sigs, enc, &open, commit_params, params);

        addProof(&sig, signature_len, trap_points[open], points, trap_sigs[open], sigs, &keys[open], enc, params, commit_params);
	}

	for (int i = 0; i < params->threshold; ++i) {
		freeViews(commits[i].views, commit_params);
		freeSeeds(commits[i].seeds);
		freeCommitments(commits[i].as);
		freeGCommitments(commits[i].gs);
	}

	for (int i = 0; i < params->ringSize - params->threshold; ++i)
		freeSignature(&sigs[i], commit_params);

	for (int o = 0; o < params->numOpenings; ++o) {
		for (int i = 0; i < params->threshold; ++i)
			freeSignature(&trap_sigs[o][i], commit_params);

		free(trap_points[o]);
		free(trap_sigs[o]);
	}

	free(commits);
	free(enc);
	free(keys);
	free(points);
	free(sigs);
	free(tests);
	free(trap_points);
	free(trap_sigs);
}

int
pqtr_verify(picnic_publickey_t *pks, const char *message, size_t message_len,
			  const uint8_t *signature, size_t signature_len, pqtr_params_t *params, paramset_t *commit_params)
{
	field_t *points, *poly, *tests;
	signature_t *sigs;
	uint8_t *key, *enc, open;
	size_t encSize;

	encSize = getEncSize(params, commit_params);

	enc = calloc(params->numOpenings, encSize);
	key = calloc(params->numProofs, params->keySize);
	points = calloc(params->ringSize, sizeof(*points));
	sigs = calloc(params->ringSize, sizeof(*sigs));

	memcpy(points, signature, params->ringSize * sizeof(field_t));
	signature += params->ringSize * sizeof(field_t);

	for (int i = 0; i < params->ringSize; ++i) {
		allocateSignature(&sigs[i], commit_params);

		if (deserializeSignature(&sigs[i], signature, signature_len, commit_params) != EXIT_SUCCESS) {
			fprintf(stderr, "can't deserialize signature for point %d\n", i);
			return EXIT_FAILURE;
		}

		signature += getSigSize(commit_params);

		if (verify2(&sigs[i], (uint32_t *)pks[i].ciphertext, (uint32_t *)pks[i].plaintext, (uint8_t *)&points[i], sizeof(*points), commit_params) != EXIT_SUCCESS) {
			fprintf(stderr, "can't verify signature for point %d\n", i);
			return EXIT_FAILURE;
		}
	}

	memcpy(key, signature, params->keySize);
	signature += params->keySize;

	memcpy(enc, signature, params->numOpenings * encSize);
	signature += params->numOpenings * encSize;

	poly = calloc(params->ringSize + 1, sizeof(*poly));
	tests = calloc(params->numOpenings, sizeof(*tests));

	for (int o = 0; o < params->numOpenings; ++o) {
		H(message, message_len, sigs, sigs, &tests[o], params, commit_params, o);

		interpolate(poly, tests[o], points, points, 0, params->ringSize);

		// if (degree(poly, params.ringSize + 1) > params.ringSize - params.threshold)
		// 	fprintf(stderr, "not enough signers\n");
		// 	return EXIT_FAILURE;
	}

	H1(message, message_len, points, sigs, enc, &open, commit_params, params);

	for (int i = 0; i < params->ringSize; ++i)
		freeSignature(&sigs[i], commit_params);

	free(enc);
	free(key);
	free(points);
	free(poly);
	free(sigs);
	free(tests);

	return EXIT_SUCCESS;
}

int
read_file(char *fmt, char *prefix, int index, uint8_t *buf, size_t buflen)
{
	int bytesRead, fd;
	char *pathname;

	asprintf(&pathname, fmt, prefix, index);

	fd = open(pathname, O_RDONLY);

	bytesRead = read(fd, buf, buflen);

	close(fd);
	free(pathname);

	return bytesRead;
}

void
write_file(char *fmt, char *prefix, int index, uint8_t *buf, size_t buflen)
{
	FILE *f;
	char *pathname;

	asprintf(&pathname, fmt, prefix, index);

	f = fopen(pathname, "wb");

	fwrite(buf, sizeof(*buf), buflen, f);

	fclose(f);
	free(pathname);
}

int
main(int argc, char *argv[])
{
	uint8_t *buf, *sigBytes;
	char *prefix, *msg;
	int alg, bytesRequired, opt, ret;
	size_t buflen, sigBytesLen;
	pqtr_params_t params;

	ret = EXIT_FAILURE;
	params.ringSize = params.threshold = 1;
	params.numProofs = 1;
	params.numOpenings = 256;
	params.keySize = 256;
    paramset_t paramset;
	picnic_params_t parameters = Picnic_L5_UR;
	picnic_publickey_t *pks;
	picnic_privatekey_t *sks;
	msg = prefix = NULL;
	alg = NONE;

	while ((opt = getopt(argc, argv, "km:n:p:st:v")) != -1) {
		switch (opt) {
		case 'k':
			alg = KEY_GEN;
			break;
		case 'n':
			params.ringSize = strtol(optarg, NULL, 10);
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
			params.threshold = strtol(optarg, NULL, 10);
			break;
		case 'v':
			alg = VERIFY;
			break;
		default:
			fprintf(stderr, "usage: %s\n", argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (prefix == NULL) {
		fprintf(stderr, "no prefix\n");
		return EXIT_FAILURE;
	}

	get_param_set(parameters, &paramset);
	buflen = getSkSize(&paramset);
	buf = malloc(buflen);

	pks = calloc(params.ringSize, sizeof(*pks));

	switch (alg) {
	case KEY_GEN:
			sks = calloc(params.ringSize, sizeof(*sks));

			for (int i = 0; i < params.ringSize; ++i) {
				picnic_keygen(parameters, &pks[i], &sks[i]);

				bytesRequired = picnic_write_public_key(&pks[i], buf, buflen);
				write_file("%s_pk_%d", prefix, i, buf, bytesRequired);

				bytesRequired = picnic_write_private_key(&sks[i], buf, buflen);
				write_file("%s_sk_%d", prefix, i, buf, bytesRequired);
			}

			free(sks);
			break;
	case SIGN:
			if (msg == NULL) {
				fprintf(stderr, "no message to sign\n");
				ret = EXIT_FAILURE;
				break;
			}

			sks = calloc(params.threshold, sizeof(*sks));

			for (int i = 0; i < params.threshold; ++i) {
				if (read_file("%s_sk_%d", prefix, i, buf, buflen) != getSkSize(&paramset)) {
					fprintf(stderr, "bad private key\n");
					return EXIT_FAILURE;
				}
				if (picnic_read_private_key(&sks[i], buf, buflen)) {
					fprintf(stderr, "no private key\n");
					return EXIT_FAILURE;
				}
			}

			for (int i = 0; i < params.ringSize; ++i) {
				if (read_file("%s_pk_%d", prefix, i, buf, buflen) != getPkSize(&paramset)) {
					fprintf(stderr, "bad public key\n");
					return EXIT_FAILURE;
				}
				if (picnic_read_public_key(&pks[i], buf, buflen)) {
					fprintf(stderr, "no public key\n");
					return EXIT_FAILURE;
				}
			}

			pqtr_sign(sks, pks, &params, &paramset, msg, strlen(msg), &sigBytes, &sigBytesLen);
			printf("Signature Size: %lu\n", sigBytesLen);

			if (sigBytes && sigBytesLen) {
				write_file("%s_%d", "sign", 0, sigBytes, sigBytesLen);
				free(sigBytes);
			}

			free(sks);
			break;
	case VERIFY:
			for (int i = 0; i < params.ringSize; ++i) {
				if (read_file("%s_pk_%d", prefix, i, buf, buflen) != getPkSize(&paramset)) {
					fprintf(stderr, "bad public key\n");
					return EXIT_FAILURE;
				}
				if (picnic_read_public_key(&pks[i], buf, buflen)) {
					fprintf(stderr, "no public key\n");
					return EXIT_FAILURE;
				}
			}

			sigBytesLen = getProofSize(&params, &paramset);
			sigBytes = malloc(sigBytesLen);

			if (read_file("%s_%d", "sign", 0, sigBytes, sigBytesLen) == sigBytesLen)
				ret = pqtr_verify(pks, msg, strlen(msg), sigBytes, sigBytesLen, &params, &paramset);
			else {
				fprintf(stderr, "bad signature size\n");
				ret = EXIT_FAILURE;
			}

			free(sigBytes);
			break;
	default:
			fprintf(stderr, "bad alg\n");
			ret = EXIT_FAILURE;
			break;
	}

	free(buf);
	free(pks);
	return ret;
}
