// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "../src/common.h"

#define TEST() fprintf(stderr, "Running test '%s'...........\n", __FUNCTION__)
#define CHECK(cond) do { if (!(cond)) {assert(0); return EXIT_FAILURE;}   }while(0)
