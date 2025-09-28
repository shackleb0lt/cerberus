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

#include <poll.h>
#include <pthread.h>

#define TRACE_TIMEOUT_SEC 5
#define TRACE_PAYLOAD MIN_HDR_LEN
#define DEFAULT_HOP_COUNT 32
#define TOTAL_PACKET_NUM  3

typedef enum
{
    TRACE_PINGING = 0,
    TRACE_DONE = 1,
    TRACE_ERROR = 2,
} trace_state_t;

typedef struct 
{
    struct timespec time_start[TOTAL_PACKET_NUM];
    double delta[TOTAL_PACKET_NUM];
    uint32_t hop_addr;
} hop_param_t;

typedef struct
{
    char ip_str[INET6_ADDRSTRLEN];

    uint32_t src_addr;
    uint32_t dest_addr;

    int sock_fd;

    uint16_t icmp_ident;
    uint16_t data_len;

    uint8_t dist_to_host;
    uint8_t hop_arr_size;
    hop_param_t *hop_arr;
} trace_param_t;

trace_param_t trace_args;
trace_state_t g_trace_state;
pthread_cond_t g_display_cond;
pthread_mutex_t g_data_lock;

volatile sig_atomic_t g_is_timeout = false;

/**
 * Prints the usage of the executable binary
 */
void print_usage(const char* exe_name)
{
    printf("\nUsage:\n");
    printf("  %s [options] <hostname or IPv4 address>\n\n", exe_name);
    printf("Options:\n");
    printf("  %-18s Max number of hops\n",  "-m <num>");
    printf("  %-18s show usage and exit\n", "-h");
}

void timeout_handler(int sig)
{
    (void) sig;
    g_is_timeout = true;
}

int setup_timeout_handler()
{
    struct sigaction sa;

    sa.sa_handler = timeout_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    return sigaction(SIGALRM, &sa, NULL);
}

ssize_t recv_pkt(uint8_t icmp_buf[], size_t buf_len, uint32_t *recv_addr)
{
    int ret = 0;
    ssize_t offset = 0;
    ssize_t bytes_read = 0;
    uint8_t buf[UINT16_MAX] = {0};

    struct sockaddr_in r_addr = {0};
    socklen_t ra_size = SOCKADDR_SIZE;

    struct pollfd pfd;
    pfd.fd = trace_args.sock_fd;
    pfd.events = POLLIN;
    
    assert(buf_len >= (MIN_HDR_LEN + TRACE_PAYLOAD));

recv_again:
    ret = poll(&pfd, 1, TRACE_TIMEOUT_SEC * ONE_SEC_TO_MSEC);
    if (ret <= 0)
    {
        if (ret == 0 || (errno == EINTR && g_is_timeout))
            return 0;
#ifndef NDEBUG
        fprintf(stderr, "poll: [ret=%ld] %s\n", bytes_read, strerror(errno));
#endif
        return -1;
    }

    bytes_read = recvfrom(trace_args.sock_fd, buf, UINT16_MAX, 0, (struct sockaddr*)&r_addr, &ra_size);
    if (bytes_read < 0)
    {
#ifndef NDEBUG
        fprintf(stderr, "recvfrom: [ret=%ld] %s\n", bytes_read, strerror(errno));
#endif
        return -1;
    }

    if (bytes_read < (MIN_HDR_LEN + TRACE_PAYLOAD))
    {
#ifndef NDEBUG
        fprintf(stderr, "%s: [bytes_read=%ld] IPv4 header size 20 bytes\n", __func__, bytes_read);
#endif
        goto recv_again;
    }

    offset = ipv4_get_ihl(buf) << 2;
    if (bytes_read <= offset)
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

    assert(ra_size == SOCKADDR_SIZE);
    (*recv_addr) = r_addr.sin_addr.s_addr;

    return bytes_read;
}

ssize_t send_pkt(uint8_t icmp_buf[], size_t buf_len, uint8_t curr_ttl)
{
    ssize_t ret = 0;
    uint8_t buf[UINT16_MAX] = {0};
    size_t tot_len = buf_len + IPV4_HDR_LEN;

    struct sockaddr_in send_addr = {0};
    send_addr.sin_addr.s_addr = trace_args.dest_addr;

    assert(buf_len <= (UINT16_MAX - IPV4_HDR_LEN));

    ipv4_set_version(buf, IP_VERSION);
    ipv4_set_ihl(buf, (IPV4_HDR_LEN / 4));

    // ipv4_set_dscp(buf, 48); // 110000 class 6 

    ipv4_set_total_length(buf, (uint16_t)tot_len);

    // ipv4_set_identification(buf, seq_num);

    ipv4_set_ttl(buf, curr_ttl);
    ipv4_set_protocol(buf, IPPROTO_ICMP);

    ipv4_set_src_ip(buf, trace_args.src_addr);
    ipv4_set_dest_ip(buf, trace_args.dest_addr);

    memcpy(buf + IPV4_HDR_LEN, icmp_buf, buf_len);
    ret = sendto(trace_args.sock_fd, buf, tot_len, 0, (struct sockaddr *)&send_addr, SOCKADDR_SIZE);

    if (ret < 0)
        fprintf(stderr, "sendto: [ret=%ld] [tot_len = %lu] %s\n", ret, tot_len, strerror(errno));

    return ret;
}

void *trace_tx_task(void *arg)
{
    (void)arg;

    ssize_t res = 0;
    uint16_t pkt_num = 0;

    uint8_t hop_num = 0;
    uint16_t seq_num = 0;

    hop_param_t *hop_ptr = NULL;

    uint8_t icmp_buf[MAX_DATA_LEN + ICMP_HDR_LEN] = {0};

    generate_icmp_data(icmp_buf, TRACE_PAYLOAD);
    icmp_set_type(icmp_buf, ICMP_ECHO);
    icmp_set_identifier(icmp_buf, trace_args.icmp_ident);

    hop_num = 1;
    seq_num = 1;

    while (hop_num <= trace_args.hop_arr_size &&
           g_trace_state == TRACE_PINGING)
    {
        for (pkt_num = 0; pkt_num < TOTAL_PACKET_NUM; pkt_num++)
        {
            if (g_trace_state != TRACE_PINGING)
                break;

            assert(seq_num == ((hop_num - 1) * TOTAL_PACKET_NUM) + pkt_num + 1);

            hop_ptr = &(trace_args.hop_arr[hop_num - 1]);
            icmp_set_sequence_number(icmp_buf, seq_num++);
            icmp_set_checksum(icmp_buf, ICMP_HDR_LEN + TRACE_PAYLOAD);

            icmp_buf[ICMP_HDR_LEN + 1] = hop_num;

            clock_gettime(CLOCK_MONOTONIC, &(hop_ptr->time_start[pkt_num]));
            res = send_pkt(icmp_buf, ICMP_HDR_LEN + TRACE_PAYLOAD, hop_num);
            if (res <= 0)
            {
                g_trace_state = TRACE_ERROR;
                return NULL;
            }

            usleep(100 * ONE_MSEC_TO_USEC);
        }
        hop_num++;
    }

    return NULL;
}

void *trace_rx_task(void *arg)
{
    (void)arg;

    double delta = 0;

    ssize_t res = 0;
    uint16_t seq_num = 0;
    uint8_t hop_num = 0;

    uint32_t recv_addr = 0;
    uint16_t pkt_num = 0;

    uint8_t *icmp_sent = NULL;
    uint8_t icmp_buf[MAX_DATA_LEN + ICMP_HDR_LEN] = {0};

    hop_param_t *hop_ptr = NULL;

    struct timespec time_end = {0};

    alarm(TRACE_TIMEOUT_SEC);

    while (g_trace_state != TRACE_ERROR)
    {
        for (hop_num = 1; hop_num <= trace_args.dist_to_host; hop_num++)
        {
            hop_ptr = &(trace_args.hop_arr[hop_num - 1]);

            if (hop_ptr->hop_addr == 0)
                break;

            if (hop_ptr->hop_addr == trace_args.dest_addr &&
                hop_ptr->delta[TOTAL_PACKET_NUM - 1] != 0)
            {
                g_trace_state = TRACE_DONE;
                goto exit_while;
            }
        }

        memset(icmp_buf, 0, ICMP_HDR_LEN + 8);
        res = recv_pkt(icmp_buf, MAX_DATA_LEN + ICMP_HDR_LEN, &recv_addr);

        clock_gettime(CLOCK_MONOTONIC, &time_end);

        if (res < 0)
        {
            g_trace_state = TRACE_ERROR;
            break;
        }
        else if (res == 0)
        {
            g_trace_state = TRACE_DONE;
            break;
        }

        if (icmp_get_type(icmp_buf) == ICMP_ECHOREPLY &&
            icmp_get_code(icmp_buf) == 0 &&
            icmp_get_identifier(icmp_buf) == trace_args.icmp_ident)
        {
            seq_num = icmp_get_sequence(icmp_buf);
            hop_num = (uint8_t) ((seq_num - 1) / 3) + 1;

            if (hop_num <= trace_args.dist_to_host)
            {
                alarm(TRACE_TIMEOUT_SEC);
                pthread_mutex_lock(&g_data_lock);

                trace_args.dist_to_host = hop_num;
                pkt_num  = (seq_num - 1) % 3;

                hop_ptr = &(trace_args.hop_arr[hop_num - 1]);

                delta = ((double)(time_end.tv_sec - hop_ptr->time_start[pkt_num].tv_sec)) * 1000.0;
                delta += ((double)(time_end.tv_nsec - hop_ptr->time_start[pkt_num].tv_nsec)) / 1000000.0;

                hop_ptr->hop_addr = recv_addr;
                hop_ptr->delta[pkt_num] = delta;
                pthread_mutex_unlock(&g_data_lock);
                pthread_cond_signal(&g_display_cond);
            }
            continue;
        }

        icmp_sent = icmp_buf + MIN_HDR_LEN;
        if (icmp_get_type(icmp_buf) == ICMP_TIME_EXCEEDED &&
            icmp_get_code(icmp_buf) == ICMP_EXC_TTL &&
            icmp_get_identifier(icmp_sent) == trace_args.icmp_ident)
        {
            seq_num = icmp_get_sequence(icmp_sent);
            hop_num = (uint8_t)  ((seq_num - 1) / 3) + 1;

            if (hop_num <= trace_args.dist_to_host)
            {
                alarm(TRACE_TIMEOUT_SEC);
                pthread_mutex_lock(&g_data_lock);

                pkt_num  = (seq_num - 1) % 3;
                hop_ptr = &(trace_args.hop_arr[hop_num - 1]);

                delta = ((double)(time_end.tv_sec - hop_ptr->time_start[pkt_num].tv_sec)) * 1000.0;
                delta += ((double)(time_end.tv_nsec - hop_ptr->time_start[pkt_num].tv_nsec)) / 1000000.0;

                if (hop_ptr->hop_addr && hop_ptr->hop_addr != recv_addr)
                    printf("Fishy stuff");
            
                hop_ptr->hop_addr = recv_addr;
                hop_ptr->delta[pkt_num] = delta;

                pthread_mutex_unlock(&g_data_lock);
                pthread_cond_signal(&g_display_cond);
            }
            continue;
        }
        else if (icmp_get_type(icmp_buf) == ICMP_DEST_UNREACH &&
                 icmp_get_identifier(icmp_sent) == trace_args.icmp_ident)
        {
            char ipstr[INET6_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &recv_addr, ipstr, INET_ADDRSTRLEN);

            printf("\nFrom %s : ", ipstr);
            print_icmp_error(icmp_buf);
            g_trace_state = TRACE_ERROR;
            break;
        }
    }

exit_while:
    alarm(0);
    pthread_cond_signal(&g_display_cond);
    return NULL;
}

void trace_print_task()
{
    char ipstr[INET6_ADDRSTRLEN] = {0};
    hop_param_t *hop_ptr = NULL;

    uint8_t hop_num = 1;
    size_t pkt_num = 0;

    pthread_mutex_lock(&g_data_lock);
    while (g_trace_state == TRACE_PINGING)
    {
        hop_ptr = &(trace_args.hop_arr[hop_num - 1]);
        if (hop_ptr->hop_addr && hop_ptr->delta[pkt_num])
        {
            if (pkt_num == 0)
                printf("%3u", hop_num);
            printf(" %7.2lf ms", hop_ptr->delta[pkt_num]);

            pkt_num++;
            if (pkt_num == TOTAL_PACKET_NUM)
            {
                inet_ntop(AF_INET, &(hop_ptr->hop_addr), ipstr, INET_ADDRSTRLEN);
                printf("   %s\n", ipstr);

                pkt_num = 0;
                hop_num++;
            }
        }
        else
        {
            pthread_cond_wait(&g_display_cond, &g_data_lock);
        }
    }
    pthread_mutex_unlock(&g_data_lock);

    if (g_trace_state == TRACE_ERROR)
        return;

    for (; hop_num <= trace_args.dist_to_host; hop_num++)
    {
        hop_ptr = &(trace_args.hop_arr[hop_num - 1]);
        if (pkt_num == 0)
            printf("%3u", hop_num);

        for (; pkt_num < TOTAL_PACKET_NUM; pkt_num++)
        {
            if (hop_ptr->hop_addr && hop_ptr->delta[pkt_num])
            {
                printf(" %7.2lf ms", hop_ptr->delta[pkt_num]);
            }
            else
            {
                printf(" %7s   ", "*");
            }
        }
        pkt_num = 0;
        if (hop_ptr->hop_addr)
        {
            inet_ntop(AF_INET, &(hop_ptr->hop_addr), ipstr, INET_ADDRSTRLEN);
            printf("   %s\n", ipstr);
        }
        else
        {
            printf("   Request timed out.\n");
        }
    }
}

int main(int argc, char *argv[])
{
    int ret = 0;
    char *hostname = NULL;
    pthread_t tx_task_id;
    pthread_t rx_task_id;

    g_trace_state = TRACE_PINGING;

    pthread_cond_init(&g_display_cond, NULL);
    pthread_mutex_init(&g_data_lock, NULL);

    memset(&trace_args, 0, sizeof(trace_param_t));
    trace_args.icmp_ident = (uint16_t) getpid();
    trace_args.hop_arr_size = DEFAULT_HOP_COUNT;
    trace_args.dist_to_host = DEFAULT_HOP_COUNT;

    while ((ret = getopt(argc, argv, "m:h")) != -1)
    {
        uint64_t res = 0;
        switch (ret)
        {
            case 'm':
            {
                if (!is_positive_integer(optarg, "max hops", 1, UINT8_MAX, &res))
                {
                    print_usage(argv[0]);
                    return EXIT_FAILURE;
                }
                trace_args.hop_arr_size = (uint8_t) res;
                trace_args.dist_to_host = (uint8_t) res;
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

    ret = get_dest_addr(hostname, &trace_args.dest_addr, trace_args.ip_str);
    if (ret != 0)
        return EXIT_FAILURE;

    ret = get_src_addr(&trace_args.src_addr, &trace_args.dest_addr);
    if(ret != 0)
        return EXIT_FAILURE;

    trace_args.sock_fd = create_raw_socket(BLOCKING_SOCK);
    if (trace_args.sock_fd < 0)
        return EXIT_FAILURE;
    
    trace_args.hop_arr = (hop_param_t *)calloc(trace_args.hop_arr_size, sizeof(hop_param_t));
    if (trace_args.hop_arr == NULL)
    {
        fprintf(stderr, "calloc failed: %s\n", strerror(errno));
        close(trace_args.sock_fd);
        return EXIT_FAILURE;
    }

    ret = setup_timeout_handler();
    if (ret)
    {
        fprintf(stderr, "Failed to setup signal handler\n");
        free(trace_args.hop_arr);
        close(trace_args.sock_fd);
        return EXIT_FAILURE;
    }

    printf("Tracing route to %s (%s)\n", hostname, trace_args.ip_str);

    ret = pthread_create(&tx_task_id, NULL, trace_tx_task, NULL);
    if (ret)
    {
        free(trace_args.hop_arr);
        close(trace_args.sock_fd);
        return EXIT_FAILURE;
    }

    ret = pthread_create(&rx_task_id, NULL, trace_rx_task, NULL);
    if (ret)
    {
        free(trace_args.hop_arr);
        close(trace_args.sock_fd);
        return EXIT_FAILURE;
    }

    trace_print_task();

    pthread_join(tx_task_id, NULL);
    pthread_join(rx_task_id, NULL);

    pthread_mutex_destroy(&g_data_lock);
    pthread_cond_destroy(&g_display_cond);

    free(trace_args.hop_arr);
    close(trace_args.sock_fd);

    fflush(stdout);
    fflush(stderr);

    if (g_trace_state == TRACE_ERROR)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}