/*  Copyright (C) 2012-2015  P.D. Buchan (pdbuchan@yahoo.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
     
    sudo route del -net 0.0.0.0 gw 192.168.1.1 netmask 0.0.0.0 dev enp0s25
	sudo route add -net 0.0.0.0 gw 192.168.1.1 netmask 0.0.0.0 dev enp0s25

	sudo route del -net 0.0.0.0 gw 10.10.10.1 netmask 0.0.0.0 dev wlp3s0
	sudo route add -net 0.0.0.0 gw 10.10.10.1 netmask 0.0.0.0 dev wlp3s0
	
	https://stackoverflow.com/questions/35068252/how-can-i-verify-if-an-url-https-exists-in-c-language
	https://www.pdbuchan.com/rawsock/rawsock.html
	* 
	* To clear ARP list, type command - "sudo ip -s -s neigh flush all"

*/

// Perform a traceroute by sending IPv4 TCP, UDP, or ICMP packets via
// raw socket at the link layer (ethernet frame).
// Need to have destination MAC address.
// TCP set for SYN, UDP for port unreachable, ICMP for echo request (ping).

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <signal.h>
#include <time.h>
 #include <ctype.h>
#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_TCP, IPPROTO_ICMP, IPPROTO_UDP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h>  // struct icmp and ICMP_TIME_EXCEEDED
#define __FAVOR_BSD           // Use BSD format of TCP header and UDP header
#include <netinet/tcp.h>      // struct tcphdr
#include <netinet/udp.h>      // struct udphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <sys/time.h>         // gettimeofday()
#include <errno.h>            // errno, perror()

#include "trace_nextHOP.h"

char interface_line[1024][1024] = {{0},{0}};

UC nextHOP		[20]	=	{0};
UC IPaddr		[20]	=	{0};
UC src_ip		[20]	=	{0};
UC MAC			[20]	=	{0};
UC interface	[20]	=	{0};

char *domain1 = "com";
char *domain2 = "co.in";
char *domain3 = "org";
char *domain4 = "net";
char *domain5 = "in";
char *domain6 = "org.net";
char *domain7 = "us";
char *domain8 = "co";
char *domain9 = "edu";
char *domain10 = "gov.in";
char *domain11 = "gov";
char *domain12 = "info";
char *domain13 = "coop";
char *domain14 = "jobs";
char *domain15 = "int";
char *domain16 = "pro";
char *domain17 = "tel";
char *domain18 = "travel";

void Debug_In_Hex_Char(UC flg,UC* buf, UI len)
{
	UI i=0;
	switch(flg)
	{
		case 1:
					for(i=0;i<len;i++)
					{
						printf("%c",buf[i]);
						//if((i+1)%20==0) 
							//printf("\n");
						fflush(stdout);
					}
					break;

		case 0:
					for(i=0;i<len;i++){
						printf("%02X",buf[i]);
						//if((i+1)%20==0) printf("\n");
					}
					printf("\n"); fflush(stdout);
					fflush(stdout);
					break;
	}
}

void exit_func(int i)
{
	signal(SIGINT,exit_func);
	exit(0);
}

void Delay_In_milliseconds(int tms)
{
    struct timeval tv;
    tv.tv_sec  = tms / 1000;
    tv.tv_usec = (tms % 1000) * 1000;
    select (0, NULL, NULL, NULL, &tv);
}

// Create a TCP ethernet frame.
int create_tcp_frame (uint8_t *snd_ether_frame, char *src_ip, char *dst_ip, uint8_t *src_mac, uint8_t *dst_mac, int ttl, uint8_t *data, int datalen)
{
	int i, status, *ip_flags, *tcp_flags;
	struct ip iphdr;
	struct tcphdr tcphdr;

	// Allocate memory for various arrays.
	ip_flags = allocate_intmem (4);
	tcp_flags = allocate_intmem (8);

	// IPv4 header

	// IPv4 header length (4 bits): Number of 32-bit words in header = 5
	iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

	// Internet Protocol version (4 bits): IPv4
	iphdr.ip_v = 4;

	// Type of service (8 bits)
	iphdr.ip_tos = 0;

	// Total length of datagram (16 bits): IP header + TCP header + data
	iphdr.ip_len = htons (IP4_HDRLEN + TCP_HDRLEN + datalen);

	// ID sequence number (16 bits): unused, since single datagram
	iphdr.ip_id = htons (0);

	// Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

	// Zero (1 bit)
	ip_flags[0] = 0;

	// Do not fragment flag (1 bit)
	ip_flags[1] = 0;

	// More fragments following flag (1 bit)
	ip_flags[2] = 0;

	// Fragmentation offset (13 bits)
	ip_flags[3] = 0;

	iphdr.ip_off = htons ((ip_flags[0] << 15)
					  + (ip_flags[1] << 14)
					  + (ip_flags[2] << 13)
					  +  ip_flags[3]);

	// Time-to-Live (8 bits): default to maximum value
	iphdr.ip_ttl = ttl;

	// Transport layer protocol (8 bits): 6 for TCP
	iphdr.ip_p = IPPROTO_TCP;

	// Source IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1)
	{
		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}

	// Destination IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1)
	{
		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}

	// IPv4 header checksum (16 bits): set to 0 when calculating checksum
	iphdr.ip_sum = 0;
	iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

	// TCP header

	// Source port number (16 bits)
	tcphdr.th_sport = htons (80);

	// Destination port number (16 bits)
	tcphdr.th_dport = htons (80);

	// Sequence number (32 bits)
	tcphdr.th_seq = htonl (0);

	// Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
	tcphdr.th_ack = htonl (0);

	// Reserved (4 bits): should be 0
	tcphdr.th_x2 = 0;

	// Data offset (4 bits): size of TCP header in 32-bit words
	tcphdr.th_off = TCP_HDRLEN / 4;

	// Flags (8 bits)

	// FIN flag (1 bit)
	tcp_flags[0] = 0;

	// SYN flag (1 bit): set to 1
	tcp_flags[1] = 1;

	// RST flag (1 bit)
	tcp_flags[2] = 0;

	// PSH flag (1 bit)
	tcp_flags[3] = 0;

	// ACK flag (1 bit)
	tcp_flags[4] = 0;

	// URG flag (1 bit)
	tcp_flags[5] = 0;

	// ECE flag (1 bit)
	tcp_flags[6] = 0;

	// CWR flag (1 bit)
	tcp_flags[7] = 0;

	tcphdr.th_flags = 0;
	
	for (i=0; i<8; i++)
	{
		tcphdr.th_flags += (tcp_flags[i] << i);
	}

	// Window size (16 bits)
	tcphdr.th_win = htons (65535);

	// Urgent pointer (16 bits): 0 (only valid if URG flag is set)
	tcphdr.th_urp = htons (0);

	// TCP checksum (16 bits)
	tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr, data, datalen);

	// Fill out ethernet frame header.

	// Destination and Source MAC addresses
	memcpy (snd_ether_frame, dst_mac, 6 * sizeof (uint8_t));
	memcpy (snd_ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

	// Next is ethernet type code (ETH_P_IP for IPv4).
	// http://www.iana.org/assignments/ethernet-numbers
	snd_ether_frame[12] = ETH_P_IP / 256;
	snd_ether_frame[13] = ETH_P_IP % 256;

	// Next is ethernet frame data (IPv4 header + TCP header).

	// IPv4 header
	memcpy (snd_ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN * sizeof (uint8_t));

	// TCP header
	memcpy (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));

	// TCP data
	memcpy (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN + TCP_HDRLEN, data, datalen * sizeof (uint8_t));

	// Free allocated memory.
	free (ip_flags);
	free (tcp_flags);

	return (EXIT_SUCCESS);
}

// Create a ICMP ethernet frame.
int create_icmp_frame (uint8_t *snd_ether_frame, char *src_ip, char *dst_ip, uint8_t *src_mac, uint8_t *dst_mac, int ttl, uint8_t *data, int datalen)
{
	int status, *ip_flags;
	struct ip iphdr;
	struct icmp icmphdr;

	// Allocate memory for various arrays.
	ip_flags = allocate_intmem (4);

	// IPv4 header

	// IPv4 header length (4 bits): Number of 32-bit words in header = 5
	iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

	// Internet Protocol version (4 bits): IPv4
	iphdr.ip_v = 4;

	// Type of service (8 bits)
	iphdr.ip_tos = 0;

	// Total length of datagram (16 bits): IP header + ICMP header + ICMP data
	iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);

	// ID sequence number (16 bits): unused, since single datagram
	iphdr.ip_id = htons (0);

	// Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

	// Zero (1 bit)
	ip_flags[0] = 0;

	// Do not fragment flag (1 bit)
	ip_flags[1] = 0;

	// More fragments following flag (1 bit)
	ip_flags[2] = 0;

	// Fragmentation offset (13 bits)
	ip_flags[3] = 0;

	iphdr.ip_off = htons ((ip_flags[0] << 15)
					  + (ip_flags[1] << 14)
					  + (ip_flags[2] << 13)
					  +  ip_flags[3]);

	// Time-to-Live (8 bits): default to maximum value
	iphdr.ip_ttl = ttl;

	// Transport layer protocol (8 bits): 1 for ICMP
	iphdr.ip_p = IPPROTO_ICMP;

	// Source IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1)
	{
		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}

	// Destination IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1)
	{
		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}

	// IPv4 header checksum (16 bits): set to 0 when calculating checksum
	iphdr.ip_sum = 0;
	iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

	// ICMP header

	// Message Type (8 bits): echo request
	icmphdr.icmp_type = ICMP_ECHO;

	// Message Code (8 bits): echo request
	icmphdr.icmp_code = 0;

	// Identifier (16 bits): usually pid of sending process - pick a number
	icmphdr.icmp_id = htons (1000);

	// Sequence Number (16 bits): starts at 0
	icmphdr.icmp_seq = htons (0);

	// ICMP header checksum (16 bits): set to 0 when calculating checksum
	icmphdr.icmp_cksum = 0;

	// Fill out ethernet frame header.

	// Destination and Source MAC addresses
	memcpy (snd_ether_frame, dst_mac, 6 * sizeof (uint8_t));
	memcpy (snd_ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

	// Next is ethernet type code (ETH_P_IP for IPv4).
	// http://www.iana.org/assignments/ethernet-numbers
	snd_ether_frame[12] = ETH_P_IP / 256;
	snd_ether_frame[13] = ETH_P_IP % 256;

	// Next is ethernet frame data (IPv4 header + ICMP header + ICMP data).

	// IPv4 header
	memcpy (snd_ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN * sizeof (uint8_t));

	// ICMP header
	memcpy (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &icmphdr, ICMP_HDRLEN * sizeof (uint8_t));

	// ICMP data
	memcpy (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN, data, datalen * sizeof (uint8_t));

	// Calcuate ICMP checksum
	icmphdr.icmp_cksum = checksum ((uint16_t *) (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN), ICMP_HDRLEN + datalen);
	memcpy (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &icmphdr, ICMP_HDRLEN * sizeof (uint8_t));

	// Free allocated memory.
	free (ip_flags);

	return (EXIT_SUCCESS);
}

// Create a UDP ethernet frame.
int create_udp_frame (uint8_t *snd_ether_frame, char *src_ip, char *dst_ip, uint8_t *src_mac, uint8_t *dst_mac, int ttl, uint8_t *data, int datalen)
{
	int status, *ip_flags;
	struct ip iphdr;
	struct udphdr udphdr;

	// Allocate memory for various arrays.
	ip_flags = allocate_intmem (4);

	// IPv4 header

	// IPv4 header length (4 bits): Number of 32-bit words in header = 5
	iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);
	
	// Internet Protocol version (4 bits): IPv4
	iphdr.ip_v = 4;
	
	// Type of service (8 bits)
	iphdr.ip_tos = 0;
	
	// Total length of datagram (16 bits): IP header + UDP header + datalen
	iphdr.ip_len = htons (IP4_HDRLEN + UDP_HDRLEN + datalen);
	
	// ID sequence number (16 bits): unused, since single datagram
	iphdr.ip_id = htons (0);
	
	// Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram
	
	// Zero (1 bit)
	ip_flags[0] = 0;
	
	// Do not fragment flag (1 bit)
	ip_flags[1] = 0;
	
	// More fragments following flag (1 bit)
	ip_flags[2] = 0;
	
	// Fragmentation offset (13 bits)
	ip_flags[3] = 0;

	iphdr.ip_off = htons ((ip_flags[0] << 15)
			  + (ip_flags[1] << 14)
			  + (ip_flags[2] << 13)
			  +  ip_flags[3]);
	
	// Time-to-Live (8 bits): default to maximum value
	iphdr.ip_ttl = ttl;
	
	// Transport layer protocol (8 bits): 17 for UDP
	iphdr.ip_p = IPPROTO_UDP;

	// Source IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1)
	{
		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}
	
	// Destination IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1)
	{
		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}
	
	// IPv4 header checksum (16 bits): set to 0 when calculating checksum
	iphdr.ip_sum = 0;
	iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);
	
	// UDP header
	
	// Source port number (16 bits): pick a number
	udphdr.uh_sport = htons (4950);
	
	// Destination port number (16 bits): pick a number
	udphdr.uh_dport = htons (33435);
	
	// Length of UDP datagram (16 bits): UDP header + UDP data
	udphdr.uh_ulen = htons (UDP_HDRLEN + datalen);
	
	// UDP checksum (16 bits)
	udphdr.uh_sum = udp4_checksum (iphdr, udphdr, data, datalen);
	
	// Fill out ethernet frame header.
	
	// Destination and Source MAC addresses
	memcpy (snd_ether_frame, dst_mac, 6 * sizeof (uint8_t));
	memcpy (snd_ether_frame + 6, src_mac, 6 * sizeof (uint8_t));
	
	// Next is ethernet type code (ETH_P_IP for IPv4).
	// http://www.iana.org/assignments/ethernet-numbers
	snd_ether_frame[12] = ETH_P_IP / 256;
	snd_ether_frame[13] = ETH_P_IP % 256;
	
	// Next is ethernet frame data (IPv4 header + UDP header + UDP data).
	// IPv4 header
	memcpy (snd_ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN * sizeof (uint8_t));
	
	// UDP header
	memcpy (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &udphdr, UDP_HDRLEN * sizeof (uint8_t));
	
	// UDP data
	memcpy (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN, data, datalen * sizeof (uint8_t));
	
	// Free allocated memory.
	free (ip_flags);
	
	return (EXIT_SUCCESS);
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t checksum (uint16_t *addr, int len)
{
	int count = len;
	register uint32_t sum = 0;
	uint16_t answer = 0;

	// Sum up 2-byte values until none or only one byte left.
	while (count > 1)
	{
		sum += *(addr++);
		count -= 2;
	}

	// Add left-over byte, if any.
	if (count > 0)
	{
		sum += *(uint8_t *) addr;
	}

	// Fold 32-bit sum into 16 bits; we lose information by doing this,
	// increasing the chances of a collision.
	// sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
	while (sum >> 16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}

	// Checksum is one's compliment of sum.
	answer = ~sum;

	return (answer);
}

// Build IPv4 TCP pseudo-header and call checksum function.
uint16_t tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr, uint8_t *payload, int payloadlen)
{
	uint16_t svalue;
	char buf[IP_MAXPACKET], cvalue;
	char *ptr;
	int chksumlen = 0;
	int i;

	ptr = &buf[0];  // ptr points to beginning of buffer buf

	// Copy source IP address into buf (32 bits)
	memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
	ptr += sizeof (iphdr.ip_src.s_addr);
	chksumlen += sizeof (iphdr.ip_src.s_addr);

	// Copy destination IP address into buf (32 bits)
	memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
	ptr += sizeof (iphdr.ip_dst.s_addr);
	chksumlen += sizeof (iphdr.ip_dst.s_addr);

	// Copy zero field to buf (8 bits)
	*ptr = 0; ptr++;
	chksumlen += 1;

	// Copy transport layer protocol to buf (8 bits)
	memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
	ptr += sizeof (iphdr.ip_p);
	chksumlen += sizeof (iphdr.ip_p);

	// Copy TCP length to buf (16 bits)
	svalue = htons (sizeof (tcphdr) + payloadlen);
	memcpy (ptr, &svalue, sizeof (svalue));
	ptr += sizeof (svalue);
	chksumlen += sizeof (svalue);

	// Copy TCP source port to buf (16 bits)
	memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
	ptr += sizeof (tcphdr.th_sport);
	chksumlen += sizeof (tcphdr.th_sport);

	// Copy TCP destination port to buf (16 bits)
	memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
	ptr += sizeof (tcphdr.th_dport);
	chksumlen += sizeof (tcphdr.th_dport);

	// Copy sequence number to buf (32 bits)
	memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
	ptr += sizeof (tcphdr.th_seq);
	chksumlen += sizeof (tcphdr.th_seq);

	// Copy acknowledgement number to buf (32 bits)
	memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
	ptr += sizeof (tcphdr.th_ack);
	chksumlen += sizeof (tcphdr.th_ack);

	// Copy data offset to buf (4 bits) and
	// copy reserved bits to buf (4 bits)
	cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
	memcpy (ptr, &cvalue, sizeof (cvalue));
	ptr += sizeof (cvalue);
	chksumlen += sizeof (cvalue);

	// Copy TCP flags to buf (8 bits)
	memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
	ptr += sizeof (tcphdr.th_flags);
	chksumlen += sizeof (tcphdr.th_flags);

	// Copy TCP window size to buf (16 bits)
	memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
	ptr += sizeof (tcphdr.th_win);
	chksumlen += sizeof (tcphdr.th_win);

	// Copy TCP checksum to buf (16 bits)
	// Zero, since we don't know it yet
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	chksumlen += 2;

	// Copy urgent pointer to buf (16 bits)
	memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
	ptr += sizeof (tcphdr.th_urp);
	chksumlen += sizeof (tcphdr.th_urp);

	// Copy payload to buf
	memcpy (ptr, payload, payloadlen);
	ptr += payloadlen;
	chksumlen += payloadlen;

	// Pad to the next 16-bit boundary
	for (i=0; i<payloadlen%2; i++, ptr++)
	{
		*ptr = 0;
		ptr++;
		chksumlen++;
	}

	return checksum ((uint16_t *) buf, chksumlen);
}

// Build IPv4 ICMP pseudo-header and call checksum function.
uint16_t icmp4_checksum (struct icmp icmphdr, uint8_t *payload, int payloadlen)
{
	char buf[IP_MAXPACKET];
	char *ptr;
	int chksumlen = 0;
	int i;

	ptr = &buf[0];  // ptr points to beginning of buffer buf

	// Copy Message Type to buf (8 bits)
	memcpy (ptr, &icmphdr.icmp_type, sizeof (icmphdr.icmp_type));
	ptr += sizeof (icmphdr.icmp_type);
	chksumlen += sizeof (icmphdr.icmp_type);

	// Copy Message Code to buf (8 bits)
	memcpy (ptr, &icmphdr.icmp_code, sizeof (icmphdr.icmp_code));
	ptr += sizeof (icmphdr.icmp_code);
	chksumlen += sizeof (icmphdr.icmp_code);

	// Copy ICMP checksum to buf (16 bits)
	// Zero, since we don't know it yet
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	chksumlen += 2;

	// Copy Identifier to buf (16 bits)
	memcpy (ptr, &icmphdr.icmp_id, sizeof (icmphdr.icmp_id));
	ptr += sizeof (icmphdr.icmp_id);
	chksumlen += sizeof (icmphdr.icmp_id);

	// Copy Sequence Number to buf (16 bits)
	memcpy (ptr, &icmphdr.icmp_seq, sizeof (icmphdr.icmp_seq));
	ptr += sizeof (icmphdr.icmp_seq);
	chksumlen += sizeof (icmphdr.icmp_seq);

	// Copy payload to buf
	memcpy (ptr, payload, payloadlen);
	ptr += payloadlen;
	chksumlen += payloadlen;

	// Pad to the next 16-bit boundary
	for (i=0; i<payloadlen%2; i++, ptr++)
	{
		*ptr = 0;
		ptr++;
		chksumlen++;
	}

	return checksum ((uint16_t *) buf, chksumlen);
}

// Build IPv4 UDP pseudo-header and call checksum function.
uint16_t udp4_checksum (struct ip iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen)
{
	char buf[IP_MAXPACKET];
	char *ptr;
	int chksumlen = 0;
	int i;

	ptr = &buf[0];  // ptr points to beginning of buffer buf

	// Copy source IP address into buf (32 bits)
	memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
	ptr += sizeof (iphdr.ip_src.s_addr);
	chksumlen += sizeof (iphdr.ip_src.s_addr);

	// Copy destination IP address into buf (32 bits)
	memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
	ptr += sizeof (iphdr.ip_dst.s_addr);
	chksumlen += sizeof (iphdr.ip_dst.s_addr);

	// Copy zero field to buf (8 bits)
	*ptr = 0; ptr++;
	chksumlen += 1;

	// Copy transport layer protocol to buf (8 bits)
	memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
	ptr += sizeof (iphdr.ip_p);
	chksumlen += sizeof (iphdr.ip_p);

	// Copy UDP length to buf (16 bits)
	memcpy (ptr, &udphdr.uh_ulen, sizeof (udphdr.uh_ulen));
	ptr += sizeof (udphdr.uh_ulen);
	chksumlen += sizeof (udphdr.uh_ulen);

	// Copy UDP source port to buf (16 bits)
	memcpy (ptr, &udphdr.uh_sport, sizeof (udphdr.uh_sport));
	ptr += sizeof (udphdr.uh_sport);
	chksumlen += sizeof (udphdr.uh_sport);

	// Copy UDP destination port to buf (16 bits)
	memcpy (ptr, &udphdr.uh_dport, sizeof (udphdr.uh_dport));
	ptr += sizeof (udphdr.uh_dport);
	chksumlen += sizeof (udphdr.uh_dport);

	// Copy UDP length again to buf (16 bits)
	memcpy (ptr, &udphdr.uh_ulen, sizeof (udphdr.uh_ulen));
	ptr += sizeof (udphdr.uh_ulen);
	chksumlen += sizeof (udphdr.uh_ulen);

	// Copy UDP checksum to buf (16 bits)
	// Zero, since we don't know it yet
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	chksumlen += 2;

	// Copy payload to buf
	memcpy (ptr, payload, payloadlen);
	ptr += payloadlen;
	chksumlen += payloadlen;

	// Pad to the next 16-bit boundary
	for (i=0; i<payloadlen%2; i++, ptr++)
	{
		*ptr = 0;
		ptr++;
		chksumlen++;
	}

	return checksum ((uint16_t *) buf, chksumlen);
}

// Allocate memory for an array of chars.
char * allocate_strmem (int len)
{
	void *tmp;
	
	if (len <= 0)
	{
		fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
		exit (EXIT_FAILURE);
	}
	
	tmp = (char *) malloc (len * sizeof (char));
	if (tmp != NULL)
	{
		memset (tmp, 0, len * sizeof (char));
		return (tmp);
	}
	else
	{
		fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
		exit (EXIT_FAILURE);
	}
}

// Allocate memory for an array of UCs.
uint8_t * allocate_ustrmem (int len)
{
	void *tmp;

	if (len <= 0) 
	{
		fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
		exit (EXIT_FAILURE);
	}
	
	tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
	if (tmp != NULL)
	{
		memset (tmp, 0, len * sizeof (uint8_t));
		return (tmp);
	}
	else
	{
		fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
		exit (EXIT_FAILURE);
	}
}

// Allocate memory for an array of ints.
int * allocate_intmem (int len)
{
	void *tmp;

	if (len <= 0)
	{
		fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
		exit (EXIT_FAILURE);
	}
	
	tmp = (int *) malloc (len * sizeof (int));
	if (tmp != NULL)
	{
		memset (tmp, 0, len * sizeof (int));
		return (tmp);
	}
	else
	{
		fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
		exit (EXIT_FAILURE);
	}
}

int validate_number(char *str)
{
	while (*str)
	{
		if(!isdigit(*str))
		{
			//if the character is not a number, returnfalse
			return 0;
		}
		
		str++; //point to next character
	}
	return 1;
}

int validate_ip(char *ip)
{
	//check whether the IP is valid or not
	int i, num, dots = 0;
	char *ptr;
	
	if (ip == NULL)
		return 0;
	
	ptr = strtok(ip, "."); //cut the string using dor delimiter
	if (ptr == NULL)
	{
		return 0;
	}
	
	while (ptr)
	{
		if (!validate_number(ptr)) //check whether the sub string is
			return 0;
		
		num = atoi(ptr); //convert substring to number
		
		if (num >= 0 && num <= 255)
		{
			ptr = strtok(NULL, "."); //cut the next part of the string
			if (ptr != NULL)
				dots++; //increase the dot count
		} 
		else
			return 0;
	}
	
	if (dots != 3) //if the number of dots are not 3, return false
		return 0;
	
	return 1;
}

int Vaildate_URL(UC *ip)
{
	int len=0;
	int i=0;
	int IpValidity=1;
	int ret=0;
	
	len = strlen(ip);
	//printf("\nLen : %d\n\n",len); fflush(stdout);
	
	for(i=0; i < len; i++)
	{
		if ((ip[i] == '!') || 
			(ip[i] == '@') || 
			(ip[i] == '#') || 
			(ip[i] == '$') || 
			(ip[i] == '%') || 
			(ip[i] == '^') || 
			(ip[i] == '&') || 
			(ip[i] == '*') || 
			(ip[i] == '(') || 
			(ip[i] == ')') || 
			(ip[i] == '\t') || 
			(ip[i] == '\b') || 
			(ip[i] == '\n')
			)
		{
			printf("\nInvaild URL, Special Character Found!. Try again\n");	fflush(stdout);
			return -1;
		}
	}
	
	if(IpValidity==1)
	{
		ret = validate_ip(ip);
		if(ret == 0)
		{
			return -1;
		}
		else
		{
			return 0;
		}
	}
	
	return 0;
}

int remove_extra_spaces(char *input)
{
	int i = 0,j,n = 0;
	
	n = strlen(input);
	
    while (i < n)
    {
        if(input[i]==' ' && (input[i+1]==' ' || input[i-1]==' '))
        {
            for(j=i;j<n;j++)
            {
				input[j]=input[j+1];
			}
			
            n--;
        }
        else
        {
            i++;
        }
    }
    
   // printf("\ninput : %s",input); fflush(stdout);
    
	n = getWords(input);

	//~ printf("nextHOP : %s %s\n",nextHOP,interface_line[0]);	fflush(stdout);
	//~ printf("nextHOP : %s %s\n",nextHOP,interface_line[1]);	fflush(stdout);
	//~ printf("nextHOP : %s %s\n",nextHOP,interface_line[2]);	fflush(stdout);
	//~ printf("nextHOP : %s %s\n",nextHOP,interface_line[3]);	fflush(stdout);
	//~ printf("nextHOP : %s %s\n",nextHOP,interface_line[4]);	fflush(stdout);
	
	if(strcmp(nextHOP , interface_line[0]) == 0)
	{
		strcpy(MAC , interface_line[2]);
		memcpy(interface , interface_line[4] , strlen(interface_line[4])-1);
		
		return 0;
	}
	
	return 1;
}

int getWords(char *base)
{
	int n=0,i,j=0;
	
	for(i=0;TRUE;i++)
	{
		if(base[i]!=' '){
			interface_line[n][j++]=base[i];
		}
		else{
			interface_line[n][j++]='\0';//insert NULL
			n++;
			j=0;
		}
		if(base[i]=='\0')
		    break;
	}
	return n;
	
}

int Fetch_MAC_And_Interface()
{
	FILE * fp=NULL;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    int found=0;
    
    UC CMD[100]={0};

    fp = fopen((char*)"arp_data" , (const char*)"r");
    if (fp == NULL)
    {
		printf("\narp_data file is not found..\n"); fflush(stdout);
		exit(EXIT_FAILURE);
	}
	
    while ((read = getline(&line, &len, fp)) != -1)
    {
        if(remove_extra_spaces(line) == 0)
        {
			found=1;
			break;
		}
    }

	fclose(fp);
	
	if(line)	free(line);
	 
	if(found==0)
	{
		return 1;
	}

    return 0;
}

UC charTohex(UC ch)
{
	if(ch>='0' && ch <= '9')
		return ch-0x30;
	else if(ch == 'A' || ch == 'a')
		return 10;
	else if(ch == 'B' || ch == 'b')
		return 11;
	else if(ch == 'C' || ch == 'c')
		return 12;
	else if(ch == 'D' || ch == 'd')
		return 13;
	else if(ch == 'E' || ch == 'e')
		return 14;
	else if(ch == 'F' || ch == 'f')
		return 15;	
}

UC str2Hex(UC * str)
{
	return charTohex(str[0])*16+charTohex(str[1]);
}

void Fetch_Interface_IP()
{
	UC CMD [200]={0};
	FILE *fp=NULL;
	int len=0;
	
	//sprintf((char*)CMD , (const char*)"ifconfig %s | egrep -o 'inet [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'  | cut -d' ' -f2 > IP_address",interface);
    sprintf((char*)CMD , (const char*)"/sbin/ifconfig %s | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}' > IP_address",interface);
	system((const char*)CMD);
	
	fp = fopen((const char*)"IP_address" , (const char*)"r");
	
	fseek(fp , 0 , SEEK_END);
	
	len = ftell(fp);
	
	fseek(fp , 0 , SEEK_SET);
	
	fread(src_ip, 1, len-1 , fp);
	
	fclose(fp);
}

int main (int argc, char **argv)
{
	int i				=	0;
	int trycount		=	0;
	int trylim			=	0;
	int node			=	0;
	int status			=	0;
	int frame_length	=	0;
	int sd				=	0;
	int sendsd			=	0;
	int recsd			=	0;
	int bytes			=	0;
	int timeout			=	0;
	int packet_type		=	0;
	int done			=	0;
	int datalen			=	0;
	int resolve			=	0;
	int maxhops			=	0;
	int probes			=	0;
	int num_probes		=	0;
	int node1			=	0;
	int MAC_Not_Found	=	0;
	
	static int try;
	
	
	char *target;
	char *dst_ip;
	char *rec_ip;
	char *tcp_dat;
	char *icmp_dat;
	char *udp_dat;
	
	UC hostname		[NI_MAXHOST] 	= {0};
	UC tempbuffer 	[20]  			= {0};
	UC CMD 			[100] 			= {0};
	UC oldIP 		[100] 			= {0};
	
	uint8_t *src_mac;
	uint8_t *dst_mac;
	uint8_t *snd_ether_frame;
	uint8_t *rec_ether_frame;
	uint8_t *data;
	
	struct ip *iphdr;
	struct tcphdr *tcphdr;
	struct icmp *icmphdr;
	struct addrinfo hints, *res;
	struct sockaddr_in *dst, sa;
	struct sockaddr from;
	struct sockaddr_ll device;
	struct ifreq ifr;
	struct timeval wait, t1, t2;
	struct timezone tz;
	
	socklen_t fromlen;
	
	double dt;
	void *tmp;
	
	// Choose whether to resolve IPs to hostnames: default to not resolve hostnames
	resolve = 0;

	// Number of probes per node.
	num_probes = 1;

	// Choose type of packet to send: 1 = TCP, 2 = ICMP, 3 = UDP
	packet_type = 2;

	// Maximum number of hops allowed.
	maxhops = 30;

	// Allocate memory for various arrays.
	tcp_dat 		= 	allocate_strmem (IP_MAXPACKET);
	icmp_dat 		= 	allocate_strmem (IP_MAXPACKET);
	udp_dat 		= 	allocate_strmem (IP_MAXPACKET);
	data 			= 	allocate_ustrmem (IP_MAXPACKET);
	rec_ip 			= 	allocate_strmem (INET_ADDRSTRLEN);
	src_mac 		= 	allocate_ustrmem (6);
	dst_mac 		= 	allocate_ustrmem (6);
	snd_ether_frame = 	allocate_ustrmem (IP_MAXPACKET);
	rec_ether_frame = 	allocate_ustrmem (IP_MAXPACKET);
	target 			= 	allocate_strmem (40);
	dst_ip 			= 	allocate_strmem (INET_ADDRSTRLEN);

	signal(SIGINT,exit_func);		/*exit function*/

	// Payloads for TCP, UDP, and ICMP packets.
	strcpy (tcp_dat, "");
	strcpy (icmp_dat, "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_");  // Seems to be commonly used, but unnecessary I think
	strcpy (udp_dat, "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_");  // Seems to be commonly used, but unnecessary I think

	system("rm arp_data IP_address");

//~ here1:
	
	printf("\nEnter address to ping : ");
	scanf("%s",IPaddr);
	
	//~ if(Vaildate_URL(IPaddr) < 0)
	//~ {
		//~ printf("\nInvalid IP address. Try again.\n\n"); fflush(stdout);
		//~ goto here1;
	//~ }

here2:	
	printf("\nEnter Next HOP IP address : ");
	scanf("%s",nextHOP);
	
	strcpy(tempbuffer , nextHOP);
	
	if(Vaildate_URL(tempbuffer) < 0)
	{
		printf("\nInvalid IP address. Try again.\n"); fflush(stdout);
		goto here2;
	}

here3:
	memset(CMD , 0x00 , sizeof(CMD));
	sprintf((char*)CMD , (const char*)"arp -n | grep '%s' > arp_data" , nextHOP);
	//printf("\nCMD : %s\n\n",CMD); fflush(stdout);
	system((const char*)CMD);
	
	////////////////////////////////////////////////////////////////////
	if(Fetch_MAC_And_Interface())
	{		
		MAC_Not_Found=1;
		
		memset(CMD , 0x00 , sizeof(CMD));
		
		sprintf((char*)CMD , (const char*)"ping -c 2 %s" , nextHOP);
		system((const char*)CMD);
		
		try++;
		
		if(try>=3)
		{
			printf("\nMAC Address is not found for the next HOP IP address...\n\n"); fflush(stdout);
			exit(1);
		}
		
		goto here3;
	}
	
	if(MAC_Not_Found==1)
	{
		MAC_Not_Found=0;
		
		printf("\nWrong MAC : %s\n",MAC); fflush(stdout);
		
		printf("\nFetching MAC address of the entered Next HOP IP. Please wait....\n"); fflush(stdout);
		
		for(i=1;i<=15;i++)
		{
			sleep(1);
			
			memset(CMD , 0x00 , sizeof(CMD));
			sprintf((char*)CMD , (const char*)"arp -n | grep '%s' > arp_data" , nextHOP);
			//printf("\nCMD : %s\n\n",CMD); fflush(stdout);
			system((const char*)CMD);
			Fetch_MAC_And_Interface();
		}
	}
	
	Fetch_Interface_IP();
	////////////////////////////////////////////////////////////////////

	printf("\nCorrect MAC address is found..\n"); fflush(stdout);
	printf("\nMAC : %s\n",MAC); fflush(stdout);
	
	// Check for acceptable payload lengths.
	if (strlen (tcp_dat) > (IP_MAXPACKET - IP4_HDRLEN - TCP_HDRLEN))
	{
		fprintf (stderr, "Maximum TCP data length exceeded. Maximum length is %i\n", IP_MAXPACKET - IP4_HDRLEN - TCP_HDRLEN);
		exit (EXIT_FAILURE);
	}
	
	if (strlen (icmp_dat) > (IP_MAXPACKET - IP4_HDRLEN - ICMP_HDRLEN))
	{
		fprintf (stderr, "Maximum ICMP data length exceeded. Maximum length is %i\n", IP_MAXPACKET - IP4_HDRLEN - ICMP_HDRLEN);
		exit (EXIT_FAILURE);
	}
	
	if (strlen (udp_dat) > (IP_MAXPACKET - IP4_HDRLEN - UDP_HDRLEN))
	{
		fprintf (stderr, "Maximum UDP data length exceeded. Maximum length is %i\n", IP_MAXPACKET - IP4_HDRLEN - UDP_HDRLEN);
		exit (EXIT_FAILURE);
	}

	// Submit request for a socket descriptor to lookup interface.
	if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
	{
		perror ("socket() failed to get socket descriptor for using ioctl() ");
		exit (EXIT_FAILURE);
	}

	// Use ioctl() to lookup interface and get MAC address.
	memset (&ifr, 0, sizeof (ifr));
	
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
	
	if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0)
	{
		perror ("ioctl() failed to get source MAC address ");
		return (EXIT_FAILURE);
	}
	
	close (sd);

	// Copy source MAC address.
	memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

	// Resolve interface index.
	memset (&device, 0, sizeof (device));
	if ((device.sll_ifindex = if_nametoindex (interface)) == 0)
	{
		perror ("if_nametoindex() failed to obtain interface index ");
		exit (EXIT_FAILURE);
	}
	
	printf ("\nInterface %s with index %i has MAC address ", interface, device.sll_ifindex);
	for (i=0; i<5; i++)
	{
		printf ("%02x:", src_mac[i]);
	}
	printf ("%02x\n", src_mac[5]);
	
		// Set destination MAC address: you need to fill these out
	dst_mac[0] = str2Hex(MAC+0);
	dst_mac[1] = str2Hex(MAC+3);
	dst_mac[2] = str2Hex(MAC+6);
	dst_mac[3] = str2Hex(MAC+9);
	dst_mac[4] = str2Hex(MAC+12);
	dst_mac[5] = str2Hex(MAC+15);
	
	// Report source MAC address to stdout.
	printf ("\nDestination MAC address for interface %s is ", interface);
	for (i=0; i<5; i++)
	{
		printf ("%02x:", dst_mac[i]);
	}
	
	printf ("%02x\n", dst_mac[5]);
	
	// Destination URL or IPv4 address: you need to fill this out
	strcpy (target, IPaddr);

	printf("\nsrc_ip : %s",src_ip); fflush(stdout);
	printf("\ntarget : %s",target); fflush(stdout);
	printf("\nNext HOP : %s",nextHOP); fflush(stdout);
	printf("\nMAC : %s",MAC); fflush(stdout);
	printf("\ninterface : %s\n\n",interface); fflush(stdout);

	// Fill out hints for getaddrinfo().
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = hints.ai_flags | AI_CANONNAME;

	// Resolve target using getaddrinfo().
	if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0)
	{
		fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
		exit (EXIT_FAILURE);
	}
	
	dst = (struct sockaddr_in *) res->ai_addr;
	tmp = &(dst->sin_addr);
	
	if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL)
	{
		status = errno;
		fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}
	
	freeaddrinfo (res);

	// Fill out sockaddr_ll.
	device.sll_family = AF_PACKET;
	memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
	device.sll_halen = 6;

	// Show target of traceroute.
	printf ("\ntraceroute to %s (%s)\n", target, dst_ip);

	// Submit request for a raw socket descriptors - one to send, one to receive.
	if ((sendsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0)
	{
		perror ("socket() failed to obtain a send socket descriptor ");
		exit(EXIT_FAILURE);
	}
	
	if ((recsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0)
	{
		perror ("socket() failed to obtain a receive socket descriptor ");
		exit (EXIT_FAILURE);
	}
	
	// Set maximum number of tries for a host before incrementing TTL and moving on.
	trylim = 1;

	// Start at TTL = 1;
	node = 1;

	// LOOP: incrementing TTL each time, exiting when we get our target IP address.
	iphdr = (struct ip *) (rec_ether_frame + ETH_HDRLEN);
	icmphdr = (struct icmp *) (rec_ether_frame + ETH_HDRLEN + IP4_HDRLEN);
	tcphdr = (struct tcphdr *) (rec_ether_frame + ETH_HDRLEN + IP4_HDRLEN);
	done = 0;
	trycount = 0;
	probes = 0;

	while(1)
	{
		//~ memset(CMD , 0x00 , sizeof(CMD));
		//~ sprintf((char*)CMD , (const char*)"arp -n | grep '%s' > arp_data" , nextHOP);
		//~ system((const char*)CMD);
		//~ Fetch_MAC_And_Interface();
		
		// Create probe packet.
		memset (snd_ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
		
		//printf("\packet_type : %d\n",packet_type); fflush(stdout);
		//printf("\nNode : %d\n",node); fflush(stdout);
		
		if (packet_type == 1)
		{
			datalen = strlen (tcp_dat);
			//printf("\ndatalen : %d",datalen); fflush(stdout);
			memcpy (data, tcp_dat, datalen * sizeof (uint8_t));
			
			create_tcp_frame (snd_ether_frame, src_ip, dst_ip, src_mac, dst_mac, node, data, datalen);
			
			// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header)
			frame_length = 6 + 6 + 2 + IP4_HDRLEN + TCP_HDRLEN + datalen;
		}
		else if (packet_type == 2)
		{
			datalen = strlen (icmp_dat);
			//printf("\ndatalen : %d",datalen); fflush(stdout);
			memcpy (data, icmp_dat, datalen * sizeof (uint8_t));
			
			create_icmp_frame (snd_ether_frame, src_ip, dst_ip, src_mac, dst_mac, node, data, datalen);
			
			// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + UDP header)
			frame_length = 6 + 6 + 2 + IP4_HDRLEN + ICMP_HDRLEN + datalen;
		}
		else if (packet_type == 3)
		{
			datalen = strlen (udp_dat);
			
			memcpy (data, udp_dat, datalen * sizeof (uint8_t));
			
			create_udp_frame (snd_ether_frame, src_ip, dst_ip, src_mac, dst_mac, node, data, datalen);
			
			// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + UDP header)
			frame_length = 6 + 6 + 2 + IP4_HDRLEN + UDP_HDRLEN + datalen;
		}
		
		//~ printf("\nNode : %d snd_ether_frame : ",node); fflush(stdout);
		//~ Debug_In_Hex_Char(0,snd_ether_frame,datalen);
		
		// Send ethernet frame to socket.
		if ((bytes = sendto (sendsd, snd_ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0)
		{
			perror ("sendto() failed");
			exit (EXIT_FAILURE);
		}
		
		probes++;
		
		//printf("\nprobes : %d node : %d\n",probes,node); fflush(stdout);
		
		// Start timer.
		(void) gettimeofday (&t1, &tz);
		
		// Set time for the socket to timeout and give up waiting for a reply.
		timeout = 2;
		wait.tv_sec  = timeout;  
		wait.tv_usec = 0;
		
		setsockopt (recsd, SOL_SOCKET, SO_RCVTIMEO, (char *) &wait, sizeof (struct timeval));
		
		// Listen for incoming ethernet frame from socket sd.
		// We expect an ICMP ethernet frame of the form:
		// MAC (6 bytes) + MAC (6 bytes) + ethernet type (2 bytes) + ethernet data (IP header + ICMP header + IP header + TCP/ICMP/UDP header)
		// Keep at it for 'timeout' seconds, or until we get an ICMP reply.
		
		//Delay_In_milliseconds(200);
		
		// RECEIVE LOOP
		while(1)
		{
			memset (rec_ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
			//memset (&from, 0, sizeof (from));
			//fromlen = sizeof (from);
			
			//printf("\nGoing to receive data..\n"); fflush(stdout);
			
			//if ((bytes = recvfrom (recsd, rec_ether_frame, IP_MAXPACKET, 0, (struct sockaddr *) &from, &fromlen)) < 0)
			bytes = recv(recsd, rec_ether_frame , IP_MAXPACKET , 0);
			//printf("\nbytes : %d",bytes); fflush(stdout);
			if (bytes<0)
			{
				status = errno;
				
				//printf("\nstatus : %02x",status); fflush(stdout);
				
				// Deal with error conditions first.
				if (status == EAGAIN)
				{
					// EAGAIN = 11
					//printf ("  %i No reply within %i seconds.\n", node, timeout);
					printf ("%2i  * * *\n",node);
					trycount++;
					break;  // Break out of Receive loop.
				}
				else if (status == EINTR)
				{
					// EINTR = 4
					continue;  // Something weird happened, but let's keep listening.
				}
				else
				{
					perror ("recvfrom() failed: \n");
					exit (EXIT_FAILURE);
				}
			}  // End of error handling conditionals.
			
			// Check for an IP ethernet frame. If not, ignore and keep listening.
			if (((rec_ether_frame[12] << 8) + rec_ether_frame[13]) == ETH_P_IP)
			{
				//~ printf("\nBytes recv : "); fflush(stdout);
				//~ Debug_In_Hex_Char(0,rec_ether_frame,bytes);
				//~ printf("\n\n");
				
				//printf("\ntrycount : %d\n",trycount); fflush(stdout);
				
				trycount++;
				
				if(trycount>=3)
				{
					Delay_In_milliseconds(100);
					//node++;
					probes = 0;
					trycount = 0;
					break;
				}
				
				//printf("\ntrycount : %d\n",trycount); fflush(stdout);
				
				// Did we get an ICMP_TIME_EXCEEDED?
				if ((iphdr->ip_p == IPPROTO_ICMP) && (icmphdr->icmp_type == ICMP_TIME_EXCEEDED))
				{
					trycount = 0;
					
					// Stop timer and calculate how long it took to get a reply.
					(void) gettimeofday (&t2, &tz);
					dt = (double) (t2.tv_sec - t1.tv_sec) * 1000.0 + (double) (t2.tv_usec - t1.tv_usec) / 1000.0;
					
					// Extract source IP address from received ethernet frame.
					if (inet_ntop (AF_INET, &(iphdr->ip_src.s_addr), rec_ip, INET_ADDRSTRLEN) == NULL)
					{
						status = errno;
						fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
						exit (EXIT_FAILURE);
					}
					
					if(strcmp(oldIP , rec_ip)==0)
					{
						//printf("\nold : %s rec_ip : %s\n",oldIP,rec_ip); fflush(stdout);
						
						node++;
						probes = 0;
						break;
					}
					else
					{
						strcpy(oldIP , rec_ip);
					}
					
					// Report source IP address and time for reply.
					if (resolve == 0)
					{
						//Debug_In_Hex_Char(0,rec_ether_frame,bytes);
						
						node1++;
						printf ("%2i  %s  %g ms (%i bytes received)", node1, oldIP, dt, bytes);
						trycount=0;
					}
					else
					{
						memset (&sa, 0, sizeof (sa));
						sa.sin_family = AF_INET;
						
						if ((status = inet_pton (AF_INET, rec_ip, &sa.sin_addr)) != 1)
						{
							fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
							exit (EXIT_FAILURE);
						}
						
						if ((status = getnameinfo ((struct sockaddr*)&sa, sizeof (sa), hostname, sizeof (hostname), NULL, 0, 0)) != 0)
						{
							fprintf (stderr, "getnameinfo() failed.\nError message: %s", strerror (status));
							exit (EXIT_FAILURE);
						}
						
						printf ("%2i  %s (%s)  %g ms (%i bytes received)", node, rec_ip, hostname, dt, bytes);
					}
					
					if (probes < num_probes)
					{
						printf (" : ");
						break;  // Break out of Receive loop and probe next node in route.
					}
					else
					{
						printf ("\n");
						node++;
						probes = 0;
						
						//~ memset (snd_ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
						
						//~ datalen = strlen (tcp_dat);
						
						//~ memcpy (data, tcp_dat, datalen * sizeof (uint8_t));
						
						//~ create_tcp_frame (snd_ether_frame, src_ip, dst_ip, src_mac, dst_mac, node, data, datalen);
						
						//~ // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header)
						//~ frame_length = 6 + 6 + 2 + IP4_HDRLEN + TCP_HDRLEN + datalen;
						
						//~ // Send ethernet frame to socket.
						//~ sendto (sendsd, snd_ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device));
						
						break;  // Break out of Receive loop and probe next node in route.
					}
				}  // End of ICMP_TIME_EXCEEDED conditional.

				// Did we reach our destination?
				// TCP SYN-ACK means TCP SYN packet reached destination node.
				// ICMP echo reply means ICMP echo request packet reached destination node.
				// ICMP port unreachable means UDP packet reached destination node.
				if ( ((iphdr->ip_p == IPPROTO_TCP) && (tcphdr->th_flags == 18)) ||
					 ((iphdr->ip_p == IPPROTO_ICMP) && (icmphdr->icmp_type == 0) && (icmphdr->icmp_code == 0)) ||  // ECHO REPLY
					 ((iphdr->ip_p == IPPROTO_ICMP) && (icmphdr->icmp_type == 3) && (icmphdr->icmp_code == 3)))
				{
					//printf("\n1111111\n\n"); fflush(stdout);
					
					// PORT UNREACHABLE
					// Stop timer and calculate how long it took to get a reply.
					(void) gettimeofday (&t2, &tz);
					
					dt = (double) (t2.tv_sec - t1.tv_sec) * 1000.0 + (double) (t2.tv_usec - t1.tv_usec) / 1000.0;
				
					// Extract source IP address from received ethernet frame.
					if (inet_ntop (AF_INET, &(iphdr->ip_src.s_addr), rec_ip, INET_ADDRSTRLEN) == NULL)
					{
						status = errno;
						fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
						exit (EXIT_FAILURE);
					}
					
					// Report source IP address and time for reply.
					//printf ("### %2i  %s  %g ms", node, rec_ip, dt);
					printf ("%2i  %s  %g ms (%i bytes received)", ++node1, rec_ip, dt, bytes); fflush(stdout);
					if (probes < num_probes)
					{
						printf (" : ");
						break;  // Break out of Receive loop and probe this node again.
					}
					else
					{
						printf ("\n");
						done = 1;
						break;  // Break out of Receive loop and finish.
					}
				}  // End of Reached Destination conditional.
			}  // End of Was IP Frame conditional.
			
		}  // End of Receive loop.
		
		//Delay_In_milliseconds(100);
		
		// Reached destination node.
		if (done == 1)
		{
			printf ("\nTraceroute complete for %s [%s].\n\n",IPaddr,dst_ip); fflush(stdout);
			break;  // Break out of Send loop.
			// Reached maxhops.
		}
		else if (node1 > maxhops)
		{
			printf ("\nReached maximum number of hops. Maximum is set to %i hops.", maxhops); fflush(stdout);
			break;  // Break out of Send loop.
		}

		// We ran out of tries, let's move on to next node unless we reached maxhops limit.
		if (trycount == trylim)
		{
			printf ("%2i  Node won't respond after %i probes.\n", node, trylim);
			node++;
			probes = 0;
			trycount = 0;
			continue;
		}
		
	}
	
	// Close socket descriptors.
	close (sendsd);
	close (recsd);

	// Free allocated memory.
	free (tcp_dat);
	free (icmp_dat);
	free (udp_dat);
	free (data);
	free (src_mac);
	free (dst_mac);
	free (snd_ether_frame);
	free (rec_ether_frame);
	free (target);
	free (dst_ip);
	free (rec_ip);

	return (EXIT_SUCCESS);
}

