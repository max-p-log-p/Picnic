#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hash.h"
#include "picnic.h"
#include "picnic_impl.h"
#include "picnic_types.h"

#define PRIME 18446744073709551557U

typedef struct pqtr_params {
	int numProofs;
	int numOpenings;
	int ringSize;
	int threshold;
	int keySize;
} pqtr_params_t;

typedef struct trap_commit {
	view_t **views;
	seeds_t *seeds;
	commitments_t *as;
	g_commitments_t *gs;
} trap_commit_t;

enum Algs { KEY_GEN, SIGN, VERIFY, NONE };

int get_param_set(picnic_params_t, paramset_t *);

typedef uint64_t field_t;

int commit(picnic_publickey_t *, const uint8_t *, size_t,
		signature_t *, paramset_t *);
int trapdoor_commit(uint32_t *, picnic_publickey_t *, view_t **, seeds_t *,
		commitments_t *, g_commitments_t *, signature_t *, paramset_t *);
int trapdoor_open(const uint8_t *, size_t, view_t **, seeds_t *,
		commitments_t *, g_commitments_t *, signature_t *, paramset_t *);
int verify2(signature_t *, const uint32_t *, const uint32_t *,
           const uint8_t *, size_t, paramset_t *);
