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

#include "common.h"

/**
 * @brief Parses a string to an unsigned 64-bit integer,
 * validating it against a specified range.
 * @param str The input string to be parsed and validated.
 * @param type A descriptive string for the field being parsed (e.g., "interval").
 * @param min The minimum allowed value (inclusive).
 * @param max The maximum allowed value (inclusive).
 * @param val A pointer to a uint64_t where the parsed value will be stored if successful.
 * @return Returns true if the string is a valid non-negative integer within the range;
 * false otherwise, printing an error to stderr.
 */
bool is_positive_integer(
    const char *str, 
    const char *type, 
    uint64_t min, 
    uint64_t max, 
    uint64_t *val)
{
    char *endptr = NULL;
    unsigned long long res_ull = 0;

    assert(type != NULL);
    assert(val != NULL);

    if (str == NULL || *str == '\0')
    {
        fprintf(stderr, "Error: %s field cannot be empty", type);
        goto print_range;
    }
    else if (*str == '-')
    {
        fprintf(stderr, "Error: %s field cannot be negative", type);
        goto print_range;
    }

    errno = 0;
    res_ull = strtoull(str, &endptr, 10);

    if (errno == ERANGE || res_ull > max || res_ull < min)
    {
        fprintf(stderr, "Error: %s value %s out of range", type, str);
        goto print_range;
    }
    else if (endptr == str || *endptr != '\0')
    {
        // No digits were found, or non-digit characters were found after valid digits
        fprintf(stderr, "Error: Invalid value '%s' for %s field (not a number)", str, type);
        goto print_range;
    }

    *val = res_ull;

#ifndef NDEBUG
    printf("Type: %s = %llu\n", type, res_ull);
#endif
    return true;

print_range:
    fprintf(stderr, ", valid range %lu <= %s <= %lu\n", min, type, max);
    return false;
}

/**
 * Prints the type of error reported by ICMP reply packet
 */
void print_icmp_error(const uint8_t *bytes)
{
    uint8_t code = icmp_get_code(bytes);
    uint8_t type = icmp_get_type(bytes);

    if(type == ICMP_DEST_UNREACH)
    {
        switch (code)
        {
            case ICMP_NET_UNREACH:
                printf("Network Unreachable\n");
                break;
            case ICMP_HOST_UNREACH:
                printf("Host Unreachable\n");
                break;
            case ICMP_PROT_UNREACH:
                printf("Protocol Unreachable\n");
                break;
            case ICMP_PORT_UNREACH:
                printf("Port Unreachable\n");
                break;
            case ICMP_FRAG_NEEDED:
                printf("Fragmentation Needed And DF Set\n");
                break;
            case ICMP_SR_FAILED:
                printf("Source Route Failed\n");
                break;
            default:
                printf("Received type: %u code: %u\n", type, code);
                break;
        }
    }
    else if(type == ICMP_TIME_EXCEEDED)
    {
        switch (code)
        {
            case ICMP_EXC_TTL:
                printf("Time To Live Exceeded In Transit\n");
                break;
            case ICMP_EXC_FRAGTIME:
                printf("Fragment Reassembly Time Exceeded\n");
                break;
            default:
                printf("Received type: %u code: %u\n", type, code);
                break;
        }
    }
    else
    {
        printf("Received type: %u code: %u\n", type, code);
    }
}

/**
 * Creates a RAW ipv4 socket allowing handcrafted 
 * ipv4 header and icmp header, requires root priveleges
 */
int create_raw_socket()
{
    int opt = 1;
    int ret = 0;
    int sock_fd = -1;
    struct timeval tv_out =
    {
        .tv_sec = 2,
        .tv_usec = 0
    };

    // Open raw socket to send packets into
    sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock_fd < 0)
    {
        perror("Failed to create ICMP socket");
        return -1;
    }

    // Enable IP_HDRINCL to tell the kernel we are including the IP header
    ret = setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(int));
    if (ret < 0)
    {
        perror("Error setting IP_HDRINCL");
        close(sock_fd);
        return -1;
    }

    // Set timeout at socket level to avoid handling it at user level
    ret = setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_out, sizeof tv_out);
    if (ret < 0)
    {
        perror("Ping interval setting failed");
        close(sock_fd);
        return -1;
    }

    // Drop root priveleges
    if (setgid(getgid()) != 0 || setuid(getuid()) != 0)
    {
        perror("Unable to drop priveleges");
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

/**
 * Convert hostname or ipv4 address string to network form
 * and stores it in addr pointer
 * Also returns a static string which hold presentation form
 */
int get_dest_addr(const char *input, uint32_t *dest_addr, char *ipstr)
{
    int ret = 0;
    struct addrinfo hint;
    struct addrinfo *res = NULL;

    assert(ipstr != NULL);
    assert(dest_addr != NULL);

    // Check if string is of the form "X.X.X.X"
    ret = inet_pton(AF_INET, input, dest_addr);
    if (ret == 1)
    {
        strncpy(ipstr, input, INET6_ADDRSTRLEN - 1);
        return 0;
    }

    // If a hostname was provided retreive it's ip address 
    memset(&hint, 0, sizeof(struct addrinfo));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_RAW;
    hint.ai_protocol = IPPROTO_ICMP;
    hint.ai_flags = 0;

    ret = getaddrinfo(input, NULL, &hint, &res);
    if (ret != 0 || res == NULL)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return -1;
    }

    (*dest_addr) = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);

    // Convert the ip adddress to presentation form to be printed
    inet_ntop(AF_INET, dest_addr, ipstr, INET6_ADDRSTRLEN);
    return 0;
}

/**
 * Work around to retreive the source IP address by
 * attempting to connect to a destination port
 * since a UDP socket is used no packets are actually sent
 */
int get_src_addr(uint32_t *src_addr, uint32_t *dest_addr)
{
    int sock_fd = -1;
    struct sockaddr_in addr = {0};
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);

    // Create a socket
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0)
    {
        perror("UDP Socket creation failed");
        return -1;
    }

    // Set up the destination address
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80); // Port doesn't matter
    addr.sin_addr.s_addr = *dest_addr;

    // Connect to the target (no data is sent)
    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Connect failed");
        close(sock_fd);
        return -1;
    }

    // Get the local interface used for the connection
    if (getsockname(sock_fd, (struct sockaddr *)&local_addr, &addr_len) < 0)
    {
        perror("getsockname failed");
        close(sock_fd);
        return -1;
    }
    
    (*src_addr) = local_addr.sin_addr.s_addr;
    close(sock_fd);
    return 0;
}

void generate_icmp_data(uint8_t buf[], size_t len)
{
    size_t i = 0;
    len += ICMP_HDR_LEN;
    for (i = ICMP_HDR_LEN; i < len; i++)
    {
        buf[i] = 'a' + (char)(i % 26);
    }
}
