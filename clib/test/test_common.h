#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "../src/common.h"

#define TEST() fprintf(stderr, "Running test '%s'...........\n", __FUNCTION__)
#define CHECK(cond) do { if (!(cond)) {assert(0); return EXIT_FAILURE;}   }while(0)
