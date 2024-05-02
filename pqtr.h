#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "picnic.h"
#include "picnic_impl.h"

enum Algs { KEY_GEN, SIGN, VERIFY };

#define NUM_COMMITS 128
