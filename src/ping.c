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

#include "ping.h"
#include <signal.h>

#define IPHDR_SIZE sizeof(struct iphdr)
#define ICMPHDR_SIZE sizeof(struct icmphdr)

#define SOCKADDR_SIZE sizeof(struct sockaddr_in)
#define MTU_SIZE 1500
#define DEFAULT_COUNT 1000
#define ONE_SEC 1000000
#define ONE_MSEC 1000

bool is_run = true;
bool is_quiet = false;
char *exe_name = NULL;

uint32_t ttl_val = 64;
uint64_t count_limit = DEFAULT_COUNT;
uint32_t interval = ONE_SEC;
uint32_t pkt_sent = 0;
uint32_t pkt_recv = 0;

double avg_time = 0;
double min_time = ONE_SEC;
double max_time = 0;

/**
 * Prints the usage of the executable binary
 */
void print_usage()
{
    printf("\nUsage:\n");
    printf("  %s [options] <destination>\n\n", exe_name);
    printf("Options:\n");
    printf("  %-18s dns name or ip address\n", "<destination>");
    printf("  %-18s number of packets sent\n", "-c <count>");
    printf("  %-18s time in milliseconds between each ping\n", "-i <interval>");
    printf("  %-18s configure time to live range 1 to 64\n", "-t <ttl value>");
    printf("  %-18s quiet output\n", "-q");
    printf("  %-18s show usage and exit\n", "-h");
}

/**
 * Catches the registered signals and ignores repeated signals
 * Sets the is_run flag to false effectively ending the ping loop
 */
void handle_signal(int sig)
{
    struct sigaction sa;
    is_run = false;
    sa.sa_flags = 0;
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);
}

/**
 * Prints the statistics of the outoging and incoming ICMP packets.
 */
void print_stats(const char *hostname)
{
    double pkt_loss = 0;
    pkt_loss = (pkt_sent - pkt_recv) * 100.0 / pkt_sent;
    printf("\n--- %s ping statistics ---\n", hostname);
    printf("%u packets transmitted, %u received, %.2lf%% packet loss\n",
           pkt_sent, pkt_recv, pkt_loss);
    printf("rtt min/avg/max = %.3lf/%.3lf/%.3lf ms\n", min_time, avg_time / pkt_recv, max_time);
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
 * Function to register signal handler during initialisation
 * allows to catch interrupt signals and gracefully exit
 */
int register_sighandler()
{
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGTERM, &sa, NULL) == -1)
    {
        fprintf(stderr, "sigaction: SIGTERM");
        return -1;
    }
    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        fprintf(stderr, "sigaction: SIGINT");
        return -1;
    }
    if (sigaction(SIGHUP, &sa, NULL) == -1)
    {
        fprintf(stderr, "sigaction: SIGHUP");
        return -1;
    }
    if (sigaction(SIGQUIT, &sa, NULL) == -1)
    {
        fprintf(stderr, "sigaction: SIGHUP");
        return -1;
    }
    return 0;
}

/**
 * Creates a RAW ipv4 socket allowing handcrafted 
 * ipv4 header and icmp header, requires root priveleges
 */
int create_socket()
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
char *get_dest_addr(const char *input, struct in_addr *dest_addr)
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
int get_src_addr(struct in_addr *src_addr, struct in_addr *dest_addr)
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
 * Function to fill ipv4 and icmp headers
 */
void fill_packet_headers(char *buf_out, struct in_addr *src_addr, struct in_addr *dest_addr)
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
 * Main loop which sends and receives the ICMP packets
 */
void ping_loop(int sock_fd, struct in_addr *src_addr, struct in_addr *dest_addr)
{
    ssize_t ret = 0;
    double delta = 0;
    uint16_t seq_num = 0;

    char buf_in[MTU_SIZE] = {0};
    char buf_out[MTU_SIZE] = {0};
    char ipstr[INET_ADDRSTRLEN] = {0};

    struct sockaddr_in send_addr = {0};

    struct iphdr *ip_hdr = NULL;
    struct icmphdr *icmp_hdr = NULL;

    struct timespec time_end = {0};
    struct timespec time_start = {0};
    struct in_addr recv_addr = {0};

    send_addr.sin_addr.s_addr = dest_addr->s_addr;
    fill_packet_headers(buf_out, src_addr, dest_addr);

    while (is_run && pkt_sent < count_limit)
    {
        // Uppdate ICMP sequence number and checksum
        icmp_hdr = (struct icmphdr *)(buf_out + IPHDR_SIZE);
        icmp_hdr->un.echo.sequence = ++seq_num;
        icmp_hdr->checksum = 0;
        icmp_hdr->checksum = inet_cksum((uint16_t *)icmp_hdr, ICMPHDR_SIZE >> 1);

        clock_gettime(CLOCK_MONOTONIC, &time_start);
        ret = sendto(sock_fd, buf_out, IPHDR_SIZE + ICMPHDR_SIZE, 0, (struct sockaddr *) &send_addr, SOCKADDR_SIZE);
        if (ret <= 0)
        {
            perror("sendto");
            continue;
        }
        pkt_sent++;
        ret = recv(sock_fd, buf_in, MTU_SIZE, 0);
        if (ret < 0)
        {
            if(errno != EAGAIN && errno != EWOULDBLOCK)
                perror("recv");

            // send next packet if timeout is reached
            continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &time_end);

        ip_hdr = (struct iphdr *)buf_in;
        icmp_hdr = (struct icmphdr *)(buf_in + (ip_hdr->ihl << 2));

        recv_addr.s_addr = ip_hdr->saddr;
        inet_ntop(AF_INET, &recv_addr, ipstr, INET_ADDRSTRLEN);

        if ((icmp_hdr->type == ICMP_ECHO || icmp_hdr->type == ICMP_ECHOREPLY) && icmp_hdr->code == 0)
        {
            delta = (time_end.tv_sec - time_start.tv_sec) * 1000.0;
            delta += (time_end.tv_nsec - time_start.tv_nsec) / 1000000.0;
            if (min_time > delta)
                min_time = delta;
            if (max_time < delta)
                max_time = delta;

            avg_time += delta;

            if (!is_quiet)
            {
                printf("%ld bytes from %s: icmp_seq=%d time=%.2lfms\n", ret, ipstr, icmp_hdr->un.echo.sequence, delta);
            }
            pkt_recv++;
        }
        else
        {
            // If response is not of type ECHOREPLY
            // Parse the code for error and print to stdout
            handle_icmp_error(ipstr, icmp_hdr);
            break;
        }

        usleep(interval);
    }
}

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

int main(int argc, char *argv[])
{
    int ret = 0;
    int sock_fd = 0;
    char *ip_str = NULL;
    char *hostname = NULL;
    struct in_addr src_addr = {0};
    struct in_addr dest_addr = {0};

    exe_name = argv[0];

    while ((ret = getopt(argc, argv, "c:i:t:qh")) != -1)
    {
        switch (ret)
        {
            case 'c':
            {
                if (!is_integer(optarg))
                {
                    printf("Error: Count not provided\n");
                    print_usage();
                    return EXIT_FAILURE;
                }
                count_limit = strtoull(optarg, NULL, 10);
                break;
            }
            case 'i':
            {
                if (!is_integer(optarg))
                {
                    printf("Error: Interval not provided\n");
                    print_usage();
                    return EXIT_FAILURE;
                }
                interval = ONE_MSEC * (uint32_t)strtoul(optarg, NULL, 10);
                break;
            }
            case 't':
            {
                if (!is_integer(optarg))
                {
                    printf("Error: Time to live not provided\n");
                    print_usage();
                    return EXIT_FAILURE;
                }
                ttl_val = (uint32_t)strtoul(optarg, NULL, 10);
                if (ttl_val > 64)
                    ttl_val = 64;
                break;
            }
            case 'q':
            {
                is_quiet = true;
                break;
            }
            case 'h':
            {
                print_usage();
                return EXIT_SUCCESS;
            }
            case '?':
            {
                print_usage();
                return EXIT_FAILURE;
            }
            default:
            {
                print_usage();
                return EXIT_FAILURE;
            }
        }
    }

    if (argv[optind] == NULL)
    {
        printf("Missing desination argument\n");
        print_usage();
        return EXIT_FAILURE;
    }
    hostname = argv[optind];

    ret = register_sighandler();
    if (ret != 0)
        return EXIT_FAILURE;

    sock_fd = create_socket();
    if (sock_fd < 0)
        return EXIT_FAILURE;

    ip_str = get_dest_addr(hostname, &dest_addr);
    if (ip_str == NULL)
    {
        close(sock_fd);
        return EXIT_FAILURE;
    }

    ret = get_src_addr(&src_addr, &dest_addr);
    if(ret != 0)
    {
        close(sock_fd);
        return EXIT_FAILURE;
    }

    printf("PING %s (%s)\n", hostname, ip_str);
    ping_loop(sock_fd, &src_addr, &dest_addr);
    print_stats(hostname);

    close(sock_fd);
    return EXIT_SUCCESS;
}