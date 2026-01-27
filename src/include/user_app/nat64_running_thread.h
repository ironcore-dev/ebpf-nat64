// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0


#ifndef NAT64_RUNNING_THREAD_H
#define NAT64_RUNNING_THREAD_H

#include <pthread.h>

#include "nat64_common.h"

int nat64_create_running_threads(void);
int nat64_stop_running_threads(void);


#endif
