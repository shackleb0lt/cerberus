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

#define ONE_MSEC 1000
#define ONE_SEC  1000000

#define DEFAULT_COUNT 1000

#define DEFAULT_TTL 64
#define IP_VERSION  4

#define MIN_HDR_LEN  (IPV4_HDR_LEN + ICMP_HDR_LEN)
#define MAX_DATA_LEN (UINT16_MAX - MIN_HDR_LEN)

#define SOCKADDR_SIZE sizeof(struct sockaddr_in)

typedef struct
{
    int sock_fd;
    int mtu_size;

    uint32_t src_addr;
    uint32_t dest_addr;

    uint32_t interval;

    uint64_t pkt_sent;
    uint64_t pkt_recv;
    uint64_t count;

    double avg_time;
    double min_time;
    double max_time;

    bool is_quiet; 
    bool is_verbose;

    uint16_t ident;
    uint16_t seq_num;

    uint8_t ttl_val;
    uint16_t data_len;

    char ip_str[INET6_ADDRSTRLEN];
} session_param;

int create_raw_socket();
int get_mtu_size(uint32_t src_addr);
ssize_t send_pkt(session_param* args, uint8_t icmp_buf[], size_t buf_len);
ssize_t recv_pkt(session_param* args, uint8_t icmp_buf[], size_t buf_len);

int get_dest_addr(const char *input, uint32_t *dest_addr, char *ip_str);
int get_src_addr(uint32_t *src_addr, uint32_t *dest_addr);

void generate_icmp_data(uint8_t buf[], size_t len);
void print_icmp_error(const uint8_t *bytes);

bool is_positive_integer(const char *str, const char *type, 
    uint64_t min, uint64_t max, uint64_t *val);


#endif