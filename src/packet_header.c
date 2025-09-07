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

#include "packet_header.h"

/**
 * @brief Calculate and returns the checksum (one's complement sum).
 * NOTE: The checksum field in the header should be set to 0 before calling this function.
 * @param data Pointer to the start of the packet.
 * @param len The total length of the packet.
 * @return The calculated 16-bit checksum in host byte order.
 */
uint16_t inet_cksum(const uint8_t *bytes, size_t len)
{
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *) bytes;

    // Sum 16-bit words
    while (len > 1)
    {
        sum += (*ptr);
        ptr++;
        len -= 2;
    }

    // Add left-over byte, if any
    if (len == 1)
    {
        sum += *(uint8_t *)ptr;
    }

    // Fold 32-bit sum to 16 bits
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)~sum;
}

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
uint8_t ipv4_get_version(const uint8_t *header_bytes)
{
    assert(header_bytes != NULL);
    // Version is in the upper 4 bits of the first byte
    return (header_bytes[0] >> 4) & 0x0F;
}

/**
 * @brief Gets the IPv4 Internet Header Length (IHL) from the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @return The 4-bit IHL (in 32-bit words).
 */
uint8_t ipv4_get_ihl(const uint8_t *header_bytes)
{
    assert(header_bytes != NULL);
    // IHL is in the lower 4 bits of the first byte
    return header_bytes[0] & 0x0F;
}

/**
 * @brief Gets the IPv4 Total Length from the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @return The 16-bit Total Length in host byte order.
 */
uint16_t ipv4_get_total_length(const uint8_t *header_bytes)
{
    uint16_t total_length;
    assert(header_bytes != NULL);
    // Copy the 2 bytes and convert from network to host byte order
    memcpy(&total_length, header_bytes + 2, sizeof(uint16_t));
    return NTOHS(total_length);
}

/**
 * @brief Gets the IPv4 Flags from the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @return The 3-bit Flags value.
 */
uint8_t ipv4_get_flags(const uint8_t *header_bytes)
{
    assert(header_bytes != NULL);
    // Flags are in the upper 3 bits of byte 6
    // Mask with 0x07 (binary 111) to get 3 bits
    return (header_bytes[6] >> 5) & 0x07; 
}

/**
 * @brief Gets the IPv4 Time to Live (TTL) from the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @return The 8-bit TTL value.
 */
uint8_t ipv4_get_ttl(const uint8_t *header_bytes)
{
    assert(header_bytes != NULL);
    return header_bytes[8];
}

/**
 * @brief Gets the IPv4 Protocol from the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @return The 8-bit Protocol value.
 */
uint8_t ipv4_get_protocol(const uint8_t *header_bytes)
{
    assert(header_bytes != NULL);
    return header_bytes[9];
}

/**
 * @brief Gets the IPv4 Source IP Address from the raw header 
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @return The 32-bit Source IP Address in network byte order.
 */
uint32_t ipv4_get_src_ip(const uint8_t *header_bytes)
{
    uint32_t ip;
    assert(header_bytes != NULL);
    memcpy(&ip, header_bytes + 12, sizeof(uint32_t));
    return ip;
}

/**
 * @brief Gets the IPv4 Destination IP Address from the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @return The 32-bit Destination IP Address in network byte order.
 */
uint32_t ipv4_get_dest_ip(const uint8_t *header_bytes)
{
    uint32_t ip;
    assert(header_bytes != NULL);
    memcpy(&ip, header_bytes + 16, sizeof(uint32_t));
    return ip;
}

/**
 * @brief Sets the IPv4 Version in the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @param version The 4-bit IPv4 version.
 */
void ipv4_set_version(uint8_t *header_bytes, uint8_t version)
{
    assert(header_bytes != NULL);
    // Clear old version and set new one
    header_bytes[0] = (header_bytes[0] & 0x0F) | ((version & 0x0F) << 4);
}

/**
 * @brief Sets the IPv4 Internet Header Length (IHL) in the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @param ihl The 4-bit IHL (in 32-bit words).
 */
void ipv4_set_ihl(uint8_t *header_bytes, uint8_t ihl)
{
    assert(header_bytes != NULL);
    // Clear old IHL and set new one
    header_bytes[0] = (header_bytes[0] & 0xF0) | (ihl & 0x0F);
}

/**
 * @brief Sets the IPv4 Total Length in the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @param total_length The 16-bit Total Length in host byte order.
 */
void ipv4_set_total_length(uint8_t *header_bytes, uint16_t total_length)
{
    uint16_t network_order_val = HTONS(total_length);
    assert(header_bytes != NULL);
    memcpy(header_bytes + 2, &network_order_val, sizeof(uint16_t));
}

/**
 * @brief Sets the Don't Fragment (DF) bit in the IPv4 header.
 *
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @param flags The value to set the bit to (0 or 1).
 */
void ipv4_set_dont_frag_bit(uint8_t *header_bytes, uint8_t flags)
{
    assert(header_bytes != NULL);
    if (flags)
        header_bytes[6] = (header_bytes[6] | 0x40);
    else
        header_bytes[6] = (header_bytes[6] & 0xbf);
}

/**
 * @brief Sets the IPv4 Flags in the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @param flags The 3-bit Flags value.
 */
void ipv4_set_flags(uint8_t *header_bytes, uint8_t flags)
{
    assert(header_bytes != NULL);
    // Preserve lower 5 bits of byte 6 (which are part of fragment offset)
    header_bytes[6] = (header_bytes[6] & 0x1F) | ((flags & 0x07) << 5);
}

/**
 * @brief Sets the IPv4 Time to Live (TTL) in the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @param ttl The 8-bit TTL value.
 */
void ipv4_set_ttl(uint8_t *header_bytes, uint8_t ttl)
{
    assert(header_bytes != NULL);
    header_bytes[8] = ttl;
}

/**
 * @brief Sets the IPv4 Protocol in the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @param protocol The 8-bit Protocol value.
 */
void ipv4_set_protocol(uint8_t *header_bytes, uint8_t protocol)
{
    assert(header_bytes != NULL);
    header_bytes[9] = protocol;
}

/**
 * @brief Sets the IPv4 Source IP Address in the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @param src_ip The 32-bit Source IP Address in network byte order.
 */
void ipv4_set_src_ip(uint8_t *header_bytes, uint32_t src_ip)
{
    assert(header_bytes != NULL);
    memcpy(header_bytes + 12, &src_ip, sizeof(uint32_t));
}

/**
 * @brief Sets the IPv4 Destination IP Address in the raw header.
 * @param header_bytes Pointer to the uint8_t array representing the IPv4 header.
 * @param dest_ip The 32-bit Destination IP Address in network byte order.
 */
void ipv4_set_dest_ip(uint8_t *header_bytes, uint32_t dest_ip)
{
    assert(header_bytes != NULL);
    memcpy(header_bytes + 16, &dest_ip, sizeof(uint32_t));
}

/**
 * @brief Util function to print the 32 bit ipv4 address in X.X.X.X notation
 * @param ip A 32bit integer storing an IPv4 address
 */
void print_ip_address(uint32_t ip, bool with_newline)
{
    printf("%u.%u.%u.%u",
           (ip >> 0) & 0xFF,
           (ip >> 8) & 0xFF,
           (ip >> 16) & 0xFF,
           (ip >> 24) & 0xFF);
    if (with_newline)
        printf("\n");
}

/**
 * @brief Function to print an IPv4 header contents
 * @param ipv4_header Pointer to the uint8_t array representing the IPv4 header.
 */
void print_ip_header(const uint8_t *ipv4_header)
{
    assert(ipv4_header != NULL);

    printf("\n------ Ipv4 Header [%p] ------\n", ipv4_header);
    printf("Version: %u\n", ipv4_get_version(ipv4_header));
    printf("IHL: %u (%u bytes)\n", ipv4_get_ihl(ipv4_header), ipv4_get_ihl(ipv4_header) * 4);
    printf("Total Length: %u\n", ipv4_get_total_length(ipv4_header));
    printf("Flags: 0x%x (Reserved: %u, DF: %u, MF: %u)\n",
           ipv4_get_flags(ipv4_header),
           (ipv4_get_flags(ipv4_header) >> 2) & 0x1, // Reserved
           (ipv4_get_flags(ipv4_header) >> 1) & 0x1, // DF
           ipv4_get_flags(ipv4_header) & 0x1         // MF
    );
    printf("TTL: %u\n", ipv4_get_ttl(ipv4_header));
    printf("Protocol: %u\n", ipv4_get_protocol(ipv4_header));
    printf("Source IP: ");
    print_ip_address(ipv4_get_src_ip(ipv4_header), false);
    printf("\n");
    printf("Destination IP: ");
    print_ip_address(ipv4_get_dest_ip(ipv4_header), false);
    printf("\n");
    printf("\n--------------------------------\n");
}

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
uint8_t icmp_get_type(const uint8_t *icmp_bytes)
{
    assert(icmp_bytes != NULL);
    return icmp_bytes[0];
}

/**
 * @brief Gets the ICMP Message Code.
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @return The 8-bit ICMP Code.
 */
uint8_t icmp_get_code(const uint8_t *icmp_bytes)
{
    assert(icmp_bytes != NULL);
    return icmp_bytes[1];
}

/**
 * @brief Gets the ICMP Checksum.
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @return The 16-bit ICMP Checksum in host byte order.
 */
uint16_t icmp_get_checksum(const uint8_t *icmp_bytes)
{
    uint16_t checksum;
    assert(icmp_bytes != NULL);
    memcpy(&checksum, icmp_bytes + 2, sizeof(uint16_t));
    return NTOHS(checksum);
}

/**
 * @brief Gets the ICMP Identifier (used by Echo Request/Reply).
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @return The 16-bit ICMP Identifier in host byte order.
 */
uint16_t icmp_get_identifier(const uint8_t *icmp_bytes)
{
    uint16_t identifier;
    assert(icmp_bytes != NULL);
    memcpy(&identifier, icmp_bytes + 4, sizeof(uint16_t));
    return NTOHS(identifier);
}

/**
 * @brief Gets the ICMP Sequence Number (used by Echo Request/Reply).
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @return The 16-bit ICMP Sequence Number in host byte order.
 */
uint16_t icmp_get_sequence(const uint8_t *icmp_bytes)
{
    uint16_t sequence_number;
    assert(icmp_bytes != NULL);
    memcpy(&sequence_number, icmp_bytes + 6, sizeof(uint16_t));
    return NTOHS(sequence_number);
}

/**
 * @brief Sets the ICMP Message Type.
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @param type The 8-bit ICMP Type.
 */
void icmp_set_type(uint8_t *icmp_bytes, uint8_t type)
{
    assert(icmp_bytes != NULL);
    icmp_bytes[0] = type;
}

/**
 * @brief Sets the ICMP Message Code.
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @param code The 8-bit ICMP Code.
 */
void icmp_set_code(uint8_t *icmp_bytes, uint8_t code)
{
    assert(icmp_bytes != NULL);
    icmp_bytes[1] = code;
}

/**
 * @brief Computes and sets the ICMP Checksum.
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @param len The total length in bytes of icmp packet
 */
void icmp_set_checksum(uint8_t *icmp_bytes, size_t len)
{
    uint16_t network_order_val;
    assert(icmp_bytes != NULL);

    if (len == 0)
        len = ICMP_HDR_LEN;
    
    icmp_bytes[2] = 0x0;
    icmp_bytes[3] = 0x0;
    network_order_val = inet_cksum(icmp_bytes, len);
    memcpy(icmp_bytes + 2, &network_order_val, sizeof(uint16_t));
}

/**
 * @brief Sets the ICMP Identifier (used by Echo Request/Reply).
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @param identifier The 16-bit ICMP Identifier in host byte order.
 */
void icmp_set_identifier(uint8_t *icmp_bytes, uint16_t identifier)
{
    uint16_t network_order_val;
    assert(icmp_bytes != NULL);
    network_order_val = HTONS(identifier);
    memcpy(icmp_bytes + 4, &network_order_val, sizeof(uint16_t));
}

/**
 * @brief Sets the ICMP Sequence Number (used by Echo Request/Reply).
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 * @param sequence_number The 16-bit ICMP Sequence Number in host byte order.
 */
void icmp_set_sequence_number(uint8_t *icmp_bytes, uint16_t sequence_number)
{
    uint16_t network_order_val;
    assert(icmp_bytes != NULL);
    network_order_val = HTONS(sequence_number);
    memcpy(icmp_bytes + 6, &network_order_val, sizeof(uint16_t));
}

/**
 * @brief Function to print an ICMP packet contents
 * @param icmp_bytes Pointer to the uint8_t array representing the ICMP packet.
 */
void print_icmp_header(const uint8_t* icmp_bytes)
{
    printf("--- Initial ICMP Packet State (All Zeros) ---\n");
    printf("Type: %u\n", icmp_get_type(icmp_bytes));
    printf("Code: %u\n", icmp_get_code(icmp_bytes));
    printf("Checksum: 0x%04x\n", icmp_get_checksum(icmp_bytes));
    printf("Identifier: %u\n", icmp_get_identifier(icmp_bytes));
    printf("Sequence Number: %u\n", icmp_get_sequence(icmp_bytes));
}
