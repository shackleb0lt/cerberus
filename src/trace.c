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

#define TIMEOUT 1000
#define DEFAULT_HOP 32
#define COUNT 16
int8_t max_ttl_val = DEFAULT_HOP;
char *exe_name = NULL;

/**
 * Prints the usage of the executable binary
 */
void print_usage()
{
    printf("\nUsage:\n");
    printf("  %s [options] <destination>\n\n", exe_name);
    printf("Options:\n");
    printf("  %-18s dns name or ip address\n", "<destination>");
    printf("  %-18s configure time to live\n", "-t <ttl value>");
    printf("  %-18s show usage and exit\n", "-h");
}

// void send_packet(int sock_fd, ipv4addr src_addr, ipv4addr dest_addr)
// {
//     int curr_ttl = 0;
//     ssize_t ret = 0;

//     bool is_run = true;

//     double delta = 0;
//     double min_time = TIMEOUT;
//     double max_time = 0;
//     double avg_time = 0;

//     uint16_t seq_num = 0;
//     uint16_t pkt_recv = 0;

//     char buf_in[MTU_SIZE] = {0};
//     char buf_out[MTU_SIZE] = {0};
//     char ipstr[INET_ADDRSTRLEN] = {0};

//     struct sockaddr_in send_addr = {0};

//     struct iphdr *ip_hdr = NULL;
//     struct icmphdr *icmp_hdr = NULL;

//     struct timespec time_end = {0};
//     struct timespec time_start = {0};
//     struct in_addr recv_addr = {0};

//     send_addr.sin_addr.s_addr = dest_addr->s_addr;

//     for (curr_ttl = 1; is_run && curr_ttl <= max_ttl_val; curr_ttl++)
//     {
//         pkt_recv = 0;
//         fill_packet_headers(buf_out, src_addr, dest_addr, curr_ttl);
//         for(seq_num = 1; seq_num <= COUNT; seq_num++)
//         {
//             icmp_hdr = (struct icmphdr *)(buf_out + IPHDR_SIZE);
//             icmp_hdr->un.echo.sequence = seq_num;
//             icmp_hdr->checksum = 0;
//             icmp_hdr->checksum = inet_cksum((uint16_t *)icmp_hdr, ICMPHDR_SIZE >> 1);

//             clock_gettime(CLOCK_MONOTONIC, &time_start);
//             ret = sendto(sock_fd, buf_out, IPHDR_SIZE + ICMPHDR_SIZE, 0, (struct sockaddr *) &send_addr, SOCKADDR_SIZE);
//             if (ret <= 0)
//             {
//                 perror("sendto");
//                 continue;
//             }
//             ret = recv(sock_fd, buf_in, MTU_SIZE, 0);
//             if (ret < 0)
//             {
//                 if(errno != EAGAIN && errno != EWOULDBLOCK)
//                     perror("recv");
//                 continue;
//             }
//             clock_gettime(CLOCK_MONOTONIC, &time_end);

//             ip_hdr = (struct iphdr *)buf_in;
//             icmp_hdr = (struct icmphdr *)(buf_in + (ip_hdr->ihl << 2));

//             recv_addr.s_addr = ip_hdr->saddr;
//             delta = (time_end.tv_sec - time_start.tv_sec) * 1000.0;
//             delta += (time_end.tv_nsec - time_start.tv_nsec) / 1000000.0;

//             if (icmp_hdr->type == ICMP_ECHOREPLY && icmp_hdr->code == 0)
//             {
//                 is_run = false;
//                 if (min_time > delta)
//                     min_time = delta;
//                 if (max_time < delta)
//                     max_time = delta;

//                 avg_time += delta;
//                 pkt_recv++;
//             }

//             if (icmp_hdr->type == ICMP_TIME_EXCEEDED && icmp_hdr->code == ICMP_EXC_TTL)
//             {

//                 if (min_time > delta)
//                     min_time = delta;
//                 if (max_time < delta)
//                     max_time = delta;

//                 avg_time += delta;
//                 pkt_recv++;
//             }
//         }

//         if(pkt_recv == 0)
//             printf("* * * *\n");
//         else
//         {
//             inet_ntop(AF_INET, &recv_addr, ipstr, INET_ADDRSTRLEN);
//             avg_time = avg_time/pkt_recv;
//             printf("%2d %-16s: %d %.2lf ms %.2lf ms %.2lf ms\n",curr_ttl, ipstr, pkt_recv, min_time, avg_time, max_time);
//         }

//     }
// }

// int main(int argc, char *argv[])
int main()
{
    // int ret = 0;
    // int sock_fd = 0;
    // char *ip_str = NULL;
    // char *hostname = NULL;
    // struct in_addr src_addr = {0};
    // struct in_addr dest_addr = {0};

    // exe_name = argv[0];

    // while ((ret = getopt(argc, argv, "t:h")) != -1)
    // {
    //     switch (ret)
    //     {
    //         case 't':
    //         {
    //             if (!is_integer(optarg))
    //             {
    //                 printf("Error: Time to live not provided\n");
    //                 print_usage();
    //                 return EXIT_FAILURE;
    //             }
    //             max_ttl_val = (uint8_t)strtoul(optarg, NULL, 10);
    //             if (max_ttl_val > 64)
    //                 max_ttl_val = 64;
    //             break;
    //         }
    //         case 'h':
    //         {
    //             print_usage();
    //             return EXIT_SUCCESS;
    //         }
    //         case '?':
    //         {
    //             print_usage();
    //             return EXIT_FAILURE;
    //         }
    //         default:
    //         {
    //             print_usage();
    //             return EXIT_FAILURE;
    //         }
    //     }
    // }

    // if (argv[optind] == NULL)
    // {
    //     printf("Missing desination argument\n");
    //     print_usage();
    //     return EXIT_FAILURE;
    // }
    // hostname = argv[optind];

    // ip_str = get_dest_addr(hostname, &dest_addr);
    // if (ip_str == NULL)
    //     return EXIT_FAILURE;

    // ret = get_src_addr(&src_addr, &dest_addr);
    // if (ret != 0)
    //     return EXIT_FAILURE;

    // sock_fd = create_socket(TIMEOUT);
    // if (sock_fd < 0)
    //     return EXIT_FAILURE;

    // printf("trace route to %s (%s)\n", hostname, ip_str);
    // send_packet(sock_fd, &src_addr, &dest_addr);

    // close(sock_fd);
    return EXIT_SUCCESS;
}