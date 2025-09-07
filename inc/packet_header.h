/**
 * MIT License
 * Copyright (c) 2025 Aniruddha Kawade
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

#ifndef PACKET_HEADER_H 
#define PACKET_HEADER_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define IS_LITTLE_ENDIAN 1
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    #define IS_LITTLE_ENDIAN 0
#else
    // Default to little-endian if unable to determine
    #warning "Cannot determine endianness at compile time. Assuming little-endian."
    #define IS_LITTLE_ENDIAN 1
#endif

#if IS_LITTLE_ENDIAN
    #if defined(__GNUC__) || defined(__clang__)
    #define HTONS(x) __builtin_bswap16(x)
    #define NTOHS(x) __builtin_bswap16(x)
    #define HTNOL(x) __builtin_bswap32(x)
    #define NTOHL(x) __builtin_bswap32(x)
    #else
    // Fallback for other compilers - less efficient but portable
    static inline uint16_t __swap16(uint16_t val) {
        return (val << 8) | (val >> 8);
    }
    static inline uint32_t __swap32(uint32_t val) {
        val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0x00FF00FF);
        return (val << 16) | (val >> 16);
    }
    #define HTONS(x) __swap16(x)
    #define NTOHS(x) __swap16(x)
    #define HTNOL(x) __swap32(x)
    #define NTOHL(x) __swap32(x)
    #endif
#else // Big-endian system, no swap needed for network order
    #define HTONS(x) (x)
    #define NTOHS(x) (x)
    #define HTNOL(x) (x)
    #define NTOHL(x) (x)
#endif /* IS_LITTLE_ENDIAN */

#define IPV4_HDR_LEN 20
#define ICMP_HDR_LEN 8

#define DEFAULT_MTU_SIZE 1500

#define DEFAULT_TTL 64
#define IP_VERSION  4

/**
 * @brief Calculate and returns the checksum (one's complement sum).
 * NOTE: The checksum field in the header should be set to 0 before calling this function.
 * @param data Pointer to the start of the packet.
 * @param len The total length of the packet.
 * @return The calculated 16-bit checksum in host byte order.
 */
uint16_t inet_cksum(const uint8_t *bytes, size_t len);

/*
    IPv4 Header Format

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * @brief Gets the IPv4 Version from the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @return The 4-bit IPv4 version.
 */
uint8_t ipv4_get_version(const uint8_t *header_bytes);

/**
 * @brief Gets the IPv4 Internet Header Length (IHL) from the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @return The 4-bit IHL (in 32-bit words).
 */
uint8_t ipv4_get_ihl(const uint8_t *header_bytes);

/**
 * @brief Gets the IPv4 Total Length from the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @return The 16-bit Total Length in host byte order.
 */
uint16_t ipv4_get_total_length(const uint8_t *header_bytes);

/**
 * @brief Gets the IPv4 Flags from the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @return The 3-bit Flags value.
 */
uint8_t ipv4_get_flags(const uint8_t *header_bytes);

/**
 * @brief Gets the IPv4 Time to Live (TTL) from the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @return The 8-bit TTL value.
 */
uint8_t ipv4_get_ttl(const uint8_t *header_bytes);

/**
 * @brief Gets the IPv4 Protocol from the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @return The 8-bit Protocol value.
 */
uint8_t ipv4_get_protocol(const uint8_t *header_bytes);

/**
 * @brief Gets the IPv4 Source IP Address from the raw header 
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @return The 32-bit Source IP Address in network byte order.
 */
uint32_t ipv4_get_src_ip(const uint8_t *header_bytes);

/**
 * @brief Gets the IPv4 Destination IP Address from the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @return The 32-bit Destination IP Address in network byte order.
 */
uint32_t ipv4_get_dest_ip(const uint8_t *header_bytes);

/**
 * @brief Sets the IPv4 Version in the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @param version The 4-bit IPv4 version.
 */
void ipv4_set_version(uint8_t *header_bytes, uint8_t version);

/**
 * @brief Sets the IPv4 Internet Header Length (IHL) in the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @param ihl The 4-bit IHL (in 32-bit words).
 */
void ipv4_set_ihl(uint8_t *header_bytes, uint8_t ihl);

/**
 * @brief Sets the IPv4 Total Length in the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @param total_length The 16-bit Total Length in host byte order.
 */
void ipv4_set_total_length(uint8_t *header_bytes, uint16_t total_length);

/**
 * @brief Sets the Don't Fragment (DF) bit in the IPv4 header.
 *
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @param flags The value to set the bit to (0 or 1).
 */
void ipv4_set_dont_frag_bit(uint8_t *header_bytes, uint8_t flags);

/**
 * @brief Sets the IPv4 Flags in the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @param flags The 3-bit Flags value.
 */
void ipv4_set_flags(uint8_t *header_bytes, uint8_t flags);

/**
 * @brief Sets the IPv4 Time to Live (TTL) in the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @param ttl The 8-bit TTL value.
 */
void ipv4_set_ttl(uint8_t *header_bytes, uint8_t ttl);

/**
 * @brief Sets the IPv4 Protocol in the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @param protocol The 8-bit Protocol value.
 */
void ipv4_set_protocol(uint8_t *header_bytes, uint8_t protocol);

/**
 * @brief Sets the IPv4 Source IP Address in the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @param src_ip The 32-bit Source IP Address in network byte order.
 */
void ipv4_set_src_ip(uint8_t *header_bytes, uint32_t src_ip);

/**
 * @brief Sets the IPv4 Destination IP Address in the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @param dest_ip The 32-bit Destination IP Address in network byte order.
 */
void ipv4_set_dest_ip(uint8_t *header_bytes, uint32_t dest_ip);

void print_ip_address(uint32_t ip, bool with_newline);
void print_ip_header(const uint8_t *ipv4_header);
void print_icmp_header(const uint8_t* icmp_bytes);

/*
    ICMP Header Format

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Data ...
   +-+-+-+-+-
*/

/**
 * @brief Gets the ICMP Message Type.
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @return The 8-bit ICMP Type.
 */
uint8_t icmp_get_type(const uint8_t *icmp_bytes);

/**
 * @brief Gets the ICMP Message Code.
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @return The 8-bit ICMP Code.
 */
uint8_t icmp_get_code(const uint8_t *icmp_bytes);

/**
 * @brief Gets the ICMP Checksum.
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @return The 16-bit ICMP Checksum in host byte order.
 */
uint16_t icmp_get_checksum(const uint8_t *icmp_bytes);

/**
 * @brief Gets the ICMP Identifier (used by Echo Request/Reply).
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @return The 16-bit ICMP Identifier in host byte order.
 */
uint16_t icmp_get_identifier(const uint8_t *icmp_bytes);

/**
 * @brief Gets the ICMP Sequence Number (used by Echo Request/Reply).
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @return The 16-bit ICMP Sequence Number in host byte order.
 */
uint16_t icmp_get_sequence(const uint8_t *icmp_bytes);

/**
 * @brief Sets the ICMP Message Type.
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @param type The 8-bit ICMP Type.
 */
void icmp_set_type(uint8_t *icmp_bytes, uint8_t type);

/**
 * @brief Sets the ICMP Message Code.
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @param code The 8-bit ICMP Code.
 */
void icmp_set_code(uint8_t *icmp_bytes, uint8_t code);

/**
 * @brief Computes and sets the ICMP Checksum.
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @param len The total length in bytes of icmp packet
 */
void icmp_set_checksum(uint8_t *icmp_bytes, size_t len);

/**
 * @brief Sets the ICMP Identifier (used by Echo Request/Reply).
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @param identifier The 16-bit ICMP Identifier in host byte order.
 */
void icmp_set_identifier(uint8_t *icmp_bytes, uint16_t identifier);

/**
 * @brief Sets the ICMP Sequence Number (used by Echo Request/Reply).
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @param sequence_number The 16-bit ICMP Sequence Number in host byte order.
 */
void icmp_set_sequence_number(uint8_t *icmp_bytes, uint16_t sequence_number);

#endif