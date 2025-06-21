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

bool is_run = true;

/**
 * Prints the usage of the executable binary
 */
void print_usage(const char *exe_name)
{
    printf("\nUsage:\n");
    printf("  %s [options] <destination>\n\n", exe_name);
    printf("Options:\n");
    printf("  %-18s hostname or IPv4 address\n", "<destination>");
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
void print_stats(session_param *args, char *hostname)
{
    double pkt_loss = 0;
    pkt_loss = (args->pkt_sent - args->pkt_recv) * 100.0 / args->pkt_sent;
    
    printf("\n--- %s ping statistics ---\n", hostname);
    printf("%lu packets transmitted, %lu received, %.2lf%% packet loss\n",
        args->pkt_sent, args->pkt_recv, pkt_loss);

    printf("rtt min/avg/max = %.3lf/%.3lf/%.3lf ms\n",
        args->min_time, args->avg_time / args->pkt_recv, args->max_time);
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

/**
 * Main loop which sends and receives the ICMP packets
 */
void ping_loop(session_param *args)
{
    ssize_t ret = 0;
    double delta = 0;

    uint8_t buf_in[MTU_SIZE] = {0};
    uint8_t buf_out[MTU_SIZE] = {0};

    uint8_t *icmp_in = buf_in + IPV4_HDR_LEN;
    uint8_t *icmp_out = buf_out + IPV4_HDR_LEN;

    uint32_t tot_len = MIN_HDR_LEN + args->data_len;

    struct timespec time_end = {0};
    struct timespec time_start = {0};
    struct sockaddr_in send_addr = {0};

    send_addr.sin_addr.s_addr = args->dest_addr;

    fill_packet_headers(buf_out, args);

    while (is_run && args->pkt_sent < args->count)
    {
//         // Update ICMP sequence number and checksum
        icmp_set_sequence_number(icmp_out, ++args->seq_num);
        icmp_set_checksum(icmp_out, ICMP_HDR_LEN + args->data_len);

        clock_gettime(CLOCK_MONOTONIC, &time_start);

        ret = sendto(args->sock_fd, buf_out, tot_len, 0, (struct sockaddr *) &send_addr, SOCKADDR_SIZE);
        if (ret <= 0)
        {
            perror("sendto");
            continue;
        }
        args->pkt_sent++;

recv_again:
        ret = recv(args->sock_fd, buf_in, MTU_SIZE, 0);
        if (ret < 0)
        {
            if(errno != EAGAIN && errno != EWOULDBLOCK)
                perror("recv");

            // send next packet if timeout is reached
            continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &time_end);
    
        if (args->dest_addr != ipv4_get_src_ip(buf_in))
            goto recv_again;

        icmp_in = buf_in + (ipv4_get_ihl(buf_in) << 2);

        if ((icmp_get_type(icmp_in) != ICMP_ECHOREPLY &&
             icmp_get_type(icmp_in) != ICMP_ECHO) ||
             icmp_get_code(icmp_in) != 0)
        {
            print_icmp_error(icmp_in);
            break;
        }

        if (args->ident != icmp_get_identifier(icmp_in))
            goto recv_again;
        else if (args->seq_num != icmp_get_sequence(icmp_in))
            goto recv_again;


        delta = (time_end.tv_sec - time_start.tv_sec) * 1000.0;
        delta += (time_end.tv_nsec - time_start.tv_nsec) / 1000000.0;
        if (args->min_time > delta)
            args->min_time = delta;
        if (args->max_time < delta)
            args->max_time = delta;

        args->avg_time += delta;

        if (!args->is_quiet)
        {
            printf("%ld bytes from %s: icmp_seq=%d time=%.2lfms\n", ret - IPV4_HDR_LEN, args->ip_str, icmp_get_sequence(icmp_in), delta);
        }
        args->pkt_recv++;
        usleep(args->interval);
    }
}

int main(int argc, char *argv[])
{
    int ret = 0;
    
    char *hostname = NULL;

    session_param ping_args = {0};

    ping_args.interval = ONE_SEC;
    ping_args.ttl_val  = DEFAULT_TTL;
    ping_args.count    = DEFAULT_COUNT;
    ping_args.min_time = ONE_SEC << 1;
    ping_args.ident = (uint16_t) getpid();

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
                if (!is_positive_integer(optarg, "ttl", 1, UINT8_MAX, &res))
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
            {
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
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
        printf("Missing desination argument\n");
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
    
    printf("PING %s (%s)\n", hostname, ping_args.ip_str);

    ping_loop(&ping_args);
    print_stats(&ping_args, hostname);

    close(ping_args.sock_fd);
    return EXIT_SUCCESS;
}