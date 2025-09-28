/**
 * MIT License
 * Copyright (c) 2024 Aniruddha Kawade
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef PING_H
#define PING_H

#include "packet_header.h"

#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

#include <time.h>
#include <errno.h>

#include <sys/socket.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#define ONE_SEC_TO_MSEC 1000
#define ONE_MSEC_TO_USEC 1000
#define ONE_SEC_TO_USEC 1000000

#define BLOCKING_SOCK SIZE_MAX
#define NON_BLOCKING_SOCK 0

#define DEFAULT_COUNT 1000

#define MIN_HDR_LEN  (IPV4_HDR_LEN + ICMP_HDR_LEN)
#define MAX_DATA_LEN (UINT16_MAX - MIN_HDR_LEN)

#define SOCKADDR_SIZE sizeof(struct sockaddr_in)

int create_raw_socket(size_t tout_ms);

int get_dest_addr(const char *input, uint32_t *dest_addr, char *ip_str);
int get_src_addr(uint32_t *src_addr, uint32_t *dest_addr);

void generate_icmp_data(uint8_t buf[], size_t len);
void print_icmp_error(const uint8_t *bytes);

bool is_positive_integer(const char *str, const char *type, 
    uint64_t min, uint64_t max, uint64_t *val);

#endif