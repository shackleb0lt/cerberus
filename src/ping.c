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

typedef struct
{
    char ip_str[INET6_ADDRSTRLEN];

    uint32_t src_addr;
    uint32_t dest_addr;

    int sock_fd;

    uint64_t pkt_sent;
    uint64_t pkt_recv;

    uint8_t ttl_val;
    uint16_t icmp_ident;
    uint16_t seq_num;
    uint16_t data_len;

    uint32_t interval;
    uint64_t count;

    double avg_time;
    double min_time;
    double max_time;

    bool is_quiet; 
    bool is_verbose;

} ping_params;


bool is_run = true;

ping_params ping_args = {0};

/**
 * Prints the usage of the executable binary
 */
void print_usage(const char *exe_name)
{
    printf("\nUsage:\n");
    printf("  %s [options] <hostname or IPv4 address>\n\n", exe_name);
    printf("Options:\n");
    printf("  %-18s Stop after <count> ping packets \n", "-c <count>");
    printf("  %-18s milliseconds between each packet\n", "-i <interval>");
    printf("  %-18s configure time to live (1-64)\n", "-t <ttl value>");
    printf("  %-18s configure icmp data payload size\n", "-s <size>");
    printf("  %-18s quiet output\n", "-q");
    printf("  %-18s verbose output\n", "-v");
    printf("  %-18s show usage and exit\n", "-h");
}

/**
 * Prints the statistics of the outoging and incoming ICMP packets.
 */
void print_stats(char *hostname)
{
    double pkt_loss = (double)(ping_args.pkt_sent - ping_args.pkt_recv);
    pkt_loss = pkt_loss * 100.0;
    pkt_loss = pkt_loss / (double)ping_args.pkt_sent;

    printf("\n--- %s ping statistics ---\n", hostname);
    printf("%lu packets transmitted, %lu received, %.2lf%% packet loss\n",
        ping_args.pkt_sent, ping_args.pkt_recv, pkt_loss);

    printf("rtt min/avg/max = %.3lf/%.3lf/%.3lf ms\n",
        ping_args.min_time, ping_args.avg_time / (double)ping_args.pkt_recv, ping_args.max_time);
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
    if (sigaction(SIGALRM, &sa, NULL) == -1)
    {
        fprintf(stderr, "sigaction: SIGHUP");
        return -1;
    }
    return 0;
}

ssize_t recv_pkt(uint8_t icmp_buf[], size_t buf_len)
{
    ssize_t offset = 0;
    ssize_t bytes_read = 0;
    uint8_t buf[UINT16_MAX] = {0};

recv_again:
    bytes_read = recv(ping_args.sock_fd, buf, UINT16_MAX, 0);
    if (bytes_read < 0)
        return -1;
    if (bytes_read <= 20)
    {
#ifndef NDEBUG
        fprintf(stderr, "%s: recv [bytes_read=%ld] <= IPv4 header size 20 bytes\n", __func__, bytes_read);
#endif
        goto recv_again;
    }

    offset = ipv4_get_ihl(buf) << 2;
    if (bytes_read - offset <= 0)
    {
#ifndef NDEBUG
        fprintf(stderr, "%s: [bytes_read=%ld] [offset=%ld]\n", __func__, bytes_read, offset);
#endif
        goto recv_again;
    }

    bytes_read -= offset;
    if ((size_t) bytes_read > buf_len)
    {
        bytes_read = (ssize_t) buf_len;
    }
    
    memcpy(icmp_buf, buf + offset, (size_t) bytes_read);
    return bytes_read;
}

ssize_t send_pkt(uint8_t icmp_buf[], size_t buf_len)
{
    ssize_t ret = 0;
    uint8_t buf[UINT16_MAX] = {0};
    size_t tot_len = buf_len + IPV4_HDR_LEN;

    struct sockaddr_in send_addr = {0};
    send_addr.sin_addr.s_addr = ping_args.dest_addr;

    ipv4_set_version(buf, IP_VERSION);
    ipv4_set_ihl(buf, (IPV4_HDR_LEN/4));

    ipv4_set_total_length(buf, (uint16_t)tot_len);

    // ipv4_set_dont_frag_bit(buf, 1);

    ipv4_set_ttl(buf, ping_args.ttl_val);
    ipv4_set_protocol(buf, IPPROTO_ICMP);

    ipv4_set_src_ip(buf, ping_args.src_addr);
    ipv4_set_dest_ip(buf, ping_args.dest_addr);

    memcpy(buf + IPV4_HDR_LEN, icmp_buf, buf_len);
    ret = sendto(ping_args.sock_fd, buf, tot_len, 0, (struct sockaddr*) &send_addr, SOCKADDR_SIZE);
#ifndef NDEBUG
    if (ret < 0)
        fprintf(stderr, "sendto: [ret=%ld] [tot_len = %lu] %s", ret, tot_len, strerror(errno));
#endif
    return ret;
}

/**
 * Main loop which sends and receives the ICMP packets
 */
void ping_loop()
{
    ssize_t ret = 0;
    double delta = 0;

    uint8_t icmp_in[MAX_DATA_LEN + ICMP_HDR_LEN] = {0};
    uint8_t icmp_out[MAX_DATA_LEN + ICMP_HDR_LEN] = {0};

    struct timespec time_end = {0};
    struct timespec time_start = {0};

    if (ping_args.data_len > 0)
    {
        generate_icmp_data(icmp_out, ping_args.data_len);
    }
    
    icmp_set_type(icmp_out, ICMP_ECHO);
    icmp_set_identifier(icmp_out, ping_args.icmp_ident);

    while (is_run && ping_args.pkt_sent < ping_args.count)
    {
        // Update ICMP sequence number and checksum
        icmp_set_sequence_number(icmp_out, ++ping_args.seq_num);
        icmp_set_checksum(icmp_out, ICMP_HDR_LEN + ping_args.data_len);

        clock_gettime(CLOCK_MONOTONIC, &time_start);

        ret = send_pkt(icmp_out, ICMP_HDR_LEN + ping_args.data_len);
        if (ret <= 0)
            break;

        ping_args.pkt_sent++;

    recv_again:
        ret = recv_pkt(icmp_in, UINT16_MAX);
        if (ret < 0)
        {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            {
                perror("recv");
                usleep(ping_args.interval);
            }
            else break;

            // send next packet if timeout is reached
            continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &time_end);

        if ((icmp_get_type(icmp_in) != ICMP_ECHOREPLY &&
             icmp_get_type(icmp_in) != ICMP_ECHO) ||
             icmp_get_code(icmp_in) != 0)
        {
            print_icmp_error(icmp_in);
            break;
        }

        if (ping_args.icmp_ident != icmp_get_identifier(icmp_in))
            goto recv_again;
        else if (ping_args.seq_num != icmp_get_sequence(icmp_in))
            goto recv_again;

        delta = ((double)(time_end.tv_sec - time_start.tv_sec)) * 1000.0;
        delta += ((double)(time_end.tv_nsec - time_start.tv_nsec)) / 1000000.0;
        if (ping_args.min_time > delta)
            ping_args.min_time = delta;
        if (ping_args.max_time < delta)
            ping_args.max_time = delta;

        ping_args.avg_time += delta;

        if (!ping_args.is_quiet)
        {
            printf("%ld bytes from %s: icmp_seq=%d time=%.2lfms\n", 
                ret, ping_args.ip_str, ping_args.seq_num, delta);
        }

        ping_args.pkt_recv++;
        usleep(ping_args.interval);
    }
}

int main(int argc, char *argv[])
{
    int ret = 0;
    char *hostname = NULL;

    memset(&ping_args, 0, sizeof(ping_params));

    ping_args.interval = ONE_SEC;
    ping_args.ttl_val  = DEFAULT_TTL;
    ping_args.count    = DEFAULT_COUNT;
    ping_args.min_time = ONE_SEC << 1;
    ping_args.icmp_ident = (uint16_t) getpid();

    while ((ret = getopt(argc, argv, "c:i:t:s:qvh")) != -1)
    {
        uint64_t res = 0;
        switch (ret)
        {
            case 'c':
            {
                if (!is_positive_integer(optarg, "count", 1, INT64_MAX, &res))
                {
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                ping_args.count = res;
                break;
            }
            case 'i':
            {
                if (!is_positive_integer(optarg, "interval", 1, INT32_MAX / ONE_MSEC, &res))
                {
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                ping_args.interval = ((uint32_t) res)* ONE_MSEC; 
                break;
            }
            case 't':
            {
                if (!is_positive_integer(optarg, "time to live", 1, UINT8_MAX, &res))
                {
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                ping_args.ttl_val = (uint8_t) res;
                break;
            }
            case 's':
            {
                if (!is_positive_integer(optarg, "size", 1, MAX_DATA_LEN, &res))
                {
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                ping_args.data_len = (uint16_t) res;
                break;
            }
            case 'q':
            {
                ping_args.is_quiet = true;
                break;
            }
            case 'v':
            {
                ping_args.is_verbose = true;
                break;
            }
            case 'h':
            {
                print_usage(argv[0]);
                return EXIT_SUCCESS;
            }
            case '?':
            default:
            {
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
        }
    }

    hostname = argv[optind];
    if (hostname == NULL)
    {
        fprintf(stderr, "Missing desination argument\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    ret = register_sighandler();
    if (ret != 0)
        return EXIT_FAILURE;

    ret = get_dest_addr(hostname, &ping_args.dest_addr, ping_args.ip_str);
    if (ret != 0)
        return EXIT_FAILURE;

    ret = get_src_addr(&ping_args.src_addr, &ping_args.dest_addr);
    if(ret != 0)
        return EXIT_FAILURE;

    ping_args.sock_fd = create_raw_socket();
    if (ping_args.sock_fd < 0)
        return EXIT_FAILURE;
    
    printf("Pinging %s (%s)\n", hostname, ping_args.ip_str);

    ping_loop();
    print_stats(hostname);

    close(ping_args.sock_fd);
    return EXIT_SUCCESS;
}