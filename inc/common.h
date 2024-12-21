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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include <time.h>
#include <errno.h>

#include <sys/socket.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#define IPHDR_SIZE sizeof(struct iphdr)
#define ICMPHDR_SIZE sizeof(struct icmphdr)

#define SOCKADDR_SIZE sizeof(struct sockaddr_in)
#define DEFAULT_COUNT 1000
#define ONE_SEC 1000000
#define ONE_MSEC 1000
#define MTU_SIZE 1500

typedef struct in_addr *ipv4addr;

int   create_socket(uint32_t interval);
int   get_src_addr(ipv4addr src_addr, ipv4addr dest_addr);
char *get_dest_addr(const char *input, ipv4addr dest_addr);

bool is_integer(char *arg);
uint16_t inet_cksum(uint16_t *buffer, const uint32_t len);
void handle_icmp_error(char *ipstr, struct icmphdr *hdr);
void fill_packet_headers(char *buf_out, ipv4addr src_addr, ipv4addr dest_addr, uint8_t ttl_val);

#endif