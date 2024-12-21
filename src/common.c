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
 * Function to verify if passed string is a number
 */
bool is_integer(char *arg)
{
    uint32_t index = 0;
    if (arg == NULL || *arg == '\0')
        return false;

    for (index = 0; arg[index] != '\0'; index++)
    {
        if (arg[index] < '0' || arg[index] > '9')
            return false;
    }
    return true;
}

/**
 * Computes and returns the internet checksum,
 * len stores the number of 2 byte elements whose 
 * checksum has to be calculated
 */
uint16_t inet_cksum(uint16_t *buffer, const uint32_t len)
{
    uint32_t sum = 0;
    uint32_t curr = 0;
    for (curr = 0; curr < len; curr++)
        sum += buffer[curr];

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = ~sum;
    return (uint16_t)sum;
}

/**
 * Prints the type of error reported by ICMP reply packet
 */
void handle_icmp_error(char *ipstr, struct icmphdr * hdr)
{
    printf("From %s icmp_seq=%d ", ipstr, hdr->un.echo.sequence);
    if(hdr->type == ICMP_DEST_UNREACH)
    {
        switch (hdr->code)
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
                printf("Received type: %d code: %d\n", hdr->type, hdr->code);
                break;
        }
    }
    else if(hdr->type == ICMP_TIME_EXCEEDED)
    {
        switch (hdr->code)
        {
            case ICMP_EXC_TTL:
                printf("Time To Live Exceeded In Transit\n");
                break;
            case ICMP_EXC_FRAGTIME:
                printf("Fragment Reassembly Time Exceeded\n");
                break;
            default:
                printf("Received type: %d code: %d\n", hdr->type, hdr->code);
                break;
        }
    }
    else
    {
        printf("Received type: %d code: %d\n", hdr->type, hdr->code);
    }
}

/**
 * Function to fill ipv4 and icmp headers
 */
void fill_packet_headers(char *buf_out, ipv4addr src_addr, ipv4addr dest_addr, uint8_t ttl_val)
{
    struct iphdr *ip_hdr = (struct iphdr *) buf_out;
    struct icmphdr *icmp_hdr = (struct icmphdr *)(buf_out + IPHDR_SIZE);

    ip_hdr->ihl = 5;
    ip_hdr->version = 4;
    ip_hdr->tot_len = htons(IPHDR_SIZE + ICMPHDR_SIZE);
    ip_hdr->id = htons((uint16_t)getpid());

    ip_hdr->ttl = ttl_val;
    ip_hdr->protocol = IPPROTO_ICMP;

    ip_hdr->saddr = src_addr->s_addr;
    ip_hdr->daddr = dest_addr->s_addr;
    
    ip_hdr->check = inet_cksum((unsigned short *)ip_hdr, IPHDR_SIZE >> 1);

    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->un.echo.id = htons((uint16_t)getpid());
}

/**
 * Creates a RAW ipv4 socket allowing handcrafted 
 * ipv4 header and icmp header, requires root priveleges
 */
int create_socket(uint32_t interval)
{
    int ret = 0;
    int sock_fd = -1;
    struct timeval tv_out = {0};
    tv_out.tv_sec = interval / ONE_SEC;
    tv_out.tv_usec = interval % ONE_SEC;

    // Open raw socket to send packets into 
    sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock_fd < 0)
    {
        perror("Failed to create ICMP socket");
        return -1;
    }

    // Enable IP_HDRINCL to tell the kernel we are including the IP header
    int opt = 1;
    ret = setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(int)); 
    if ( ret < 0)
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
char *get_dest_addr(const char *input, ipv4addr dest_addr)
{
    int ret = 0;
    struct addrinfo hint;
    struct addrinfo *res;
    static char ipstr[INET_ADDRSTRLEN] = {0};

    // Check if string is of the form "X.X.X.X"
    ret = inet_pton(AF_INET, input, dest_addr);
    if (ret == 1)
    {
        strncpy(ipstr, input, INET_ADDRSTRLEN - 1);
        return ipstr;
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
        return NULL;
    }
    dest_addr->s_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    // Convert the ip adddress to presentation form to be printed
    inet_ntop(AF_INET, dest_addr, ipstr, INET_ADDRSTRLEN);
    return ipstr;
}

/**
 * Work around to retreives the source IP address by
 * attempting to connect to a destination port
 * since the socet used is UDP no packets are actually sent
 */
int get_src_addr(ipv4addr src_addr, ipv4addr dest_addr)
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
    addr.sin_addr.s_addr = dest_addr->s_addr;

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
    
    src_addr->s_addr = local_addr.sin_addr.s_addr;
    close(sock_fd);
    return 0;
}