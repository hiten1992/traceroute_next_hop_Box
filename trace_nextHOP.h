#ifndef TRACE_NEXT_HOP
#define TRACE_NEXT_HOP

#define TRUE 1

#define UC	unsigned char 	
#define UI	unsigned int 	
#define US	unsigned short 	
#define UL	unsigned long

// Define some constants.
#define ETH_HDRLEN 14  // Ethernet header length
#define IP4_HDRLEN 20  // IPv4 header length
#define TCP_HDRLEN 20  // TCP header length, excludes options data
#define UDP_HDRLEN  8  // UDP header length, excludes data
#define ICMP_HDRLEN 8  // ICMP header length for echo request, excludes data

uint16_t	checksum 					(uint16_t *, int);
uint16_t	tcp4_checksum 				(struct ip, struct tcphdr, uint8_t *, int);
uint16_t	udp4_checksum 				(struct ip, struct udphdr, uint8_t *, int);
uint16_t	icmp4_checksum 				(struct icmp, uint8_t *, int);
int			create_tcp_frame 			(uint8_t *, char *, char *, uint8_t *, uint8_t *, int, uint8_t *, int);
int			create_udp_frame 			(uint8_t *, char *, char *, uint8_t *, uint8_t *, int, uint8_t *, int);
int			create_icmp_frame 			(uint8_t *, char *, char *, uint8_t *, uint8_t *, int, uint8_t *, int);
char 	*	allocate_strmem 			(int);
uint8_t *	allocate_ustrmem 			(int);
int 	*	allocate_intmem 			(int);
int 		validate_number				(char *str);
int 		validate_ip					(char *ip);
int 		Vaildate_URL				(UC *ip);
int 		remove_extra_spaces			(char *input);
int 		getWords					(char *base);
int 		Fetch_MAC_And_Interface		(UC *nextHOP_IP);
void 		Fetch_Interface_IP			(void);

#endif

