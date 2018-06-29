/*
 *  WrapSix
 *  Copyright (C) 2008-2017  xHire <xhire@wrapsix.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _DEFAULT_SOURCE

#include <arpa/inet.h>		/* inet_pton */
#include <linux/ethtool.h>	/* struct ethtool_value, ETHTOOL_S* */
#include <linux/if_ether.h>	/* ETH_P_ALL */
#include <linux/sockios.h>	/* SIOCETHTOOL */
#include <net/ethernet.h>	/* ETHERTYPE_* */
#include <pthread.h>		/* thread primitives */
#include <net/if.h>		/* struct ifreq */
#include <netinet/in.h>		/* htons */
#include <netpacket/packet.h>	/* struct packet_mreq, struct sockaddr_ll */
#include <stdio.h>		/* perror */
#include <stdlib.h>		/* srand */
#include <string.h>		/* strncpy */
#include <sys/ioctl.h>		/* ioctl, SIOCGIFINDEX */
#include <sys/types.h>		/* caddr_t */
#include <time.h>		/* time, time_t */
#include <unistd.h>		/* close */

#include "arp.h"
#ifdef HAVE_CONFIG_H
#include "autoconfig.h"
#endif /* HAVE_CONFIG_H */
#include "config.h"
#include "ethernet.h"
#include "icmp.h"
#include "ipv4.h"
#include "ipv6.h"
#include "log.h"
#include "nat.h"
#include "transmitter.h"
#include "wrapper.h"

unsigned short mtu;

struct ifreq		interface_ipv6;
struct ifreq		interface_ipv4;
struct s_mac_addr	mac_ipv6;
struct s_mac_addr	mac_ipv4;
struct s_ipv6_addr	ndp_multicast_addr;
struct s_ipv6_addr	wrapsix_ipv6_prefix;
struct s_ipv4_addr	wrapsix_ipv4_addr;
struct s_ipv6_addr	host_ipv6_addr;
struct s_ipv4_addr	host_ipv4_addr;

static void *sniff_ipv6(void *arg);
static void *sniff_ipv4(void *arg);
static int process(unsigned char *packet, unsigned short length, int is_ipv6);

int main(int argc, char **argv)
{
	struct s_cfg_opts	cfg;
	pthread_t thread_ipv4, thread_ipv6;

	log_info(PACKAGE_STRING " is starting");

	/* load configuration */
	if (argc == 1) {
		cfg_parse(SYSCONFDIR "/wrapsix.conf", &mtu, &cfg, 1);
	} else {
		cfg_parse(argv[1], &mtu, &cfg, 1);
	}

	log_info("Using: IPv6 interface %s", cfg.interface_ipv6);
	log_info("       IPv4 interface %s", cfg.interface_ipv4);
	log_info("       prefix %s", cfg.prefix);
	log_info("       MTU %d", mtu);
	log_info("       IPv4 address %s", cfg.ipv4_address);

	/* get host IP addresses */
	if (cfg_host_ips(&cfg, &host_ipv6_addr, &host_ipv4_addr)) {
		log_error("Unable to get host IP addresses");
		return 1;
	}
	/* using block because of the temporary variable */
	{
		char ip_text[40];

		inet_ntop(AF_INET, &host_ipv4_addr, ip_text, sizeof(ip_text));
		log_info("       host IPv4 address %s", ip_text);
		inet_ntop(AF_INET6, &host_ipv6_addr, ip_text, sizeof(ip_text));
		log_info("       host IPv6 address %s", ip_text);
	}

	/* save interface names */
	strncpy(interface_ipv6.ifr_name, cfg.interface_ipv6, IFNAMSIZ);
	strncpy(interface_ipv4.ifr_name, cfg.interface_ipv4, IFNAMSIZ);

	/* some preparations */
	/* compute binary IPv6 address of NDP multicast */
	inet_pton(AF_INET6, "ff02::1:ff00:0", &ndp_multicast_addr);

	/* compute binary IPv6 address of WrapSix prefix */
	inet_pton(AF_INET6, cfg.prefix, &wrapsix_ipv6_prefix);

	/* compute binary IPv4 address of WrapSix */
	inet_pton(AF_INET, cfg.ipv4_address, &wrapsix_ipv4_addr);

	/* initiate NAT tables */
	nat_init();

	/* initiate random numbers generator */
	srand((unsigned int) time(NULL));

	/* run sniffing threads */
	pthread_create(&thread_ipv4, NULL, sniff_ipv4, (void *) NULL);
	pthread_create(&thread_ipv6, NULL, sniff_ipv6, (void *) NULL);

	pthread_join(thread_ipv4, NULL);
	pthread_join(thread_ipv6, NULL);

	/* clean-up */
	/* close sending socket */
	transmission_quit();

	/* empty NAT tables */
	nat_quit();

	return 0;
}

static void *sniff_ipv6(void *arg)
{
	struct packet_mreq	pmr;
	struct ethtool_value	ethtool;
	struct sockaddr_ll	sa;

	int	sniff_sock;
	int	length;
	unsigned char	buffer[PACKET_BUFFER];

	int	i;
	time_t	prevtime, curtime;

	/* initialize the socket for sniffing */
	if ((sniff_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) ==
	    -1) {
		perror("socket");
		log_error("IPv6: Unable to create listening socket");
		return NULL;
	}

	/* get the interface */
	if (ioctl(sniff_sock, SIOCGIFINDEX, &interface_ipv6) == -1) {
		perror("ioctl SIOCGIFINDEX");
		log_error("IPv6: Unable to get the interface %s",
			  interface_ipv6.ifr_name);
		return NULL;
	}

	/* get interface's HW address (i.e. MAC) */
	if (ioctl(sniff_sock, SIOCGIFHWADDR, &interface_ipv6) == 0) {
		memcpy(&mac_ipv6, &interface_ipv6.ifr_hwaddr.sa_data,
		       sizeof(struct s_mac_addr));

		/* disable generic receive offload */
		ethtool.cmd = ETHTOOL_SGRO;
		ethtool.data = 0;
		interface_ipv6.ifr_data = (caddr_t) &ethtool;
		if (ioctl(sniff_sock, SIOCETHTOOL, &interface_ipv6) == -1) {
			perror("ioctl SIOCETHTOOL ETHTOOL_SGRO");
			log_warn("IPv6: Unable to disable generic receive "
				 "offload on the interface %s",
				 interface_ipv6.ifr_name);
		}

		/* disable tcp segmentation offload */
		ethtool.cmd = ETHTOOL_STSO;
		ethtool.data = 0;
		interface_ipv6.ifr_data = (caddr_t) &ethtool;
		if (ioctl(sniff_sock, SIOCETHTOOL, &interface_ipv6) == -1) {
			perror("ioctl SIOCETHTOOL ETHTOOL_STSO");
			log_warn("IPv6: Unable to disable tcp segmentation "
				 "offload on the interface %s",
				 interface_ipv6.ifr_name);
		}

		/* reinitialize the interface */
		interface_ipv6.ifr_data = NULL;
		if (ioctl(sniff_sock, SIOCGIFINDEX, &interface_ipv6) == -1) {
			perror("ioctl SIOCGIFINDEX");
			log_error("IPv6: Unable to reinitialize the interface "
				  "%s", interface_ipv6.ifr_name);
			return NULL;
		}
	} else {
		perror("ioctl SIOCGIFHWADDR");
		log_error("IPv6: Unable to get the interface's HW address %s",
			  interface_ipv6.ifr_name);
		return NULL;
	}

	/* bind to ipv6 interface */
	memset(&sa, 0, sizeof(sa));
	sa.sll_family		= AF_PACKET;
	sa.sll_ifindex		= interface_ipv6.ifr_ifindex;
	if (bind(sniff_sock, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		perror("IPv6: interface bind");
		log_error("Couldn't bind the sniffing socket to the "
			  "interface %s", interface_ipv6.ifr_name);
		return NULL;
	}

	/* set the promiscuous mode */
	memset(&pmr, 0x0, sizeof(pmr));
	pmr.mr_ifindex = interface_ipv6.ifr_ifindex;
	pmr.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(sniff_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
	    (char *) &pmr, sizeof(pmr)) == -1) {
		perror("setsockopt PACKET_ADD_MEMBERSHIP");
		log_error("IPv6: Unable to set the promiscuous mode on the "
			  "interface %s", interface_ipv6.ifr_name);
		return NULL;
	}

	/* initiate sending socket */
	if (transmission_init6()) {
		log_error("IPv6: Unable to initiate sending socket");
		return NULL;
	}

	/* initialize time */
	prevtime = time(NULL);

	/* sniff! :c) */
	for (i = 1;; i++) {
		length = recv(sniff_sock, buffer, PACKET_BUFFER, MSG_TRUNC);
		if (length == -1) {
			perror("recv");
			log_error("IPv6: Unable to retrieve data from socket");
			return NULL;
		}

		if (length > PACKET_BUFFER) {
			log_error("IPv6: Received packet is too big (%d B). "
				  "Please tune NIC offloading features and "
				  "report this issue to " PACKAGE_BUGREPORT,
				  length);
			continue;
		}

		process(buffer, length, 1);

		/* TODO: move this into it's own thread */
		if (i % 250000) {
			curtime = time(NULL);
			/* 2 seconds is minimum normal timeout */
			if ((curtime - prevtime) >= 2) {
				nat_cleaning();
				prevtime = curtime;
			}
			i = 0;
		}
	}

	/* unset the promiscuous mode */
	if (setsockopt(sniff_sock, SOL_PACKET, PACKET_DROP_MEMBERSHIP,
	    (char *) &pmr, sizeof(pmr)) == -1) {
		perror("setsockopt PACKET_DROP_MEMBERSHIP");
		log_error("IPv6: Unable to unset the promiscuous mode on the "
			  "interface %s", interface_ipv6.ifr_name);
		/* do not call return here as we want to close the socket too */
	}

	/* close the socket */
	close(sniff_sock);

	pthread_exit(NULL);

	return NULL;
}

static void *sniff_ipv4(void *arg)
{
	struct packet_mreq	pmr;
	struct ethtool_value	ethtool;
	struct sockaddr_ll	sa;

	int	sniff_sock;
	int	length;
	unsigned char	buffer[PACKET_BUFFER];

	int	i;
	time_t	prevtime, curtime;

	/* initialize the socket for sniffing */
	if ((sniff_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) ==
	    -1) {
		perror("socket");
		log_error("IPv4: Unable to create listening socket");
		return NULL;
	}

	/* get the interface */
	if (ioctl(sniff_sock, SIOCGIFINDEX, &interface_ipv4) == -1) {
		perror("ioctl SIOCGIFINDEX");
		log_error("IPv4: Unable to get the interface %s",
			  interface_ipv4.ifr_name);
		return NULL;
	}

	/* get interface's HW address (i.e. MAC) */
	if (ioctl(sniff_sock, SIOCGIFHWADDR, &interface_ipv4) == 0) {
		memcpy(&mac_ipv4, &interface_ipv4.ifr_hwaddr.sa_data,
		       sizeof(struct s_mac_addr));

		/* disable generic receive offload */
		ethtool.cmd = ETHTOOL_SGRO;
		ethtool.data = 0;
		interface_ipv4.ifr_data = (caddr_t) &ethtool;
		if (ioctl(sniff_sock, SIOCETHTOOL, &interface_ipv4) == -1) {
			perror("ioctl SIOCETHTOOL ETHTOOL_SGRO");
			log_warn("IPv4: Unable to disable generic receive "
				 "offload on the interface %s",
				 interface_ipv4.ifr_name);
		}

		/* disable tcp segmentation offload */
		ethtool.cmd = ETHTOOL_STSO;
		ethtool.data = 0;
		interface_ipv4.ifr_data = (caddr_t) &ethtool;
		if (ioctl(sniff_sock, SIOCETHTOOL, &interface_ipv4) == -1) {
			perror("ioctl SIOCETHTOOL ETHTOOL_STSO");
			log_warn("IPv4: Unable to disable tcp segmentation "
				 "offload on the interface %s",
				 interface_ipv4.ifr_name);
		}

		/* reinitialize the interface */
		interface_ipv4.ifr_data = NULL;
		if (ioctl(sniff_sock, SIOCGIFINDEX, &interface_ipv4) == -1) {
			perror("ioctl SIOCGIFINDEX");
			log_error("IPv4: Unable to reinitialize the interface "
				  "%s", interface_ipv4.ifr_name);
			return NULL;
		}
	} else {
		perror("ioctl SIOCGIFHWADDR");
		log_error("IPv4: Unable to get the interface's HW address %s",
			  interface_ipv4.ifr_name);
		return NULL;
	}

	/* bind to ipv6 interface */
	memset(&sa, 0, sizeof(sa));
	sa.sll_family		= AF_PACKET;
	sa.sll_ifindex		= interface_ipv4.ifr_ifindex;
	if (bind(sniff_sock, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		perror("IPv4: interface bind");
		log_error("Couldn't bind the sniffing socket to the "
			  "interface %s", interface_ipv4.ifr_name);
		return NULL;
	}

	/* set the promiscuous mode */
	memset(&pmr, 0x0, sizeof(pmr));
	pmr.mr_ifindex = interface_ipv4.ifr_ifindex;
	pmr.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(sniff_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
	    (char *) &pmr, sizeof(pmr)) == -1) {
		perror("setsockopt PACKET_ADD_MEMBERSHIP");
		log_error("IPv4: Unable to set the promiscuous mode on the "
			  "interface %s", interface_ipv4.ifr_name);
		return NULL;
	}

	/* initiate sending socket */
	if (transmission_init4()) {
		log_error("IPv4: Unable to initiate sending socket");
		return NULL;
	}

	/* initialize time */
	prevtime = time(NULL);

	/* sniff! :c) */
	for (i = 1;; i++) {
		length = recv(sniff_sock, buffer, PACKET_BUFFER, MSG_TRUNC);
		if (length == -1) {
			perror("recv");
			log_error("IPv4: Unable to retrieve data from socket");
			return NULL;
		}

		if (length > PACKET_BUFFER) {
			log_error("IPv4: Received packet is too big (%d B). "
				  "Please tune NIC offloading features and "
				  "report this issue to " PACKAGE_BUGREPORT,
				  length);
			continue;
		}

		process(buffer, length, 0);

		/* TODO: move this into it's own thread */
		if (i % 250000) {
			curtime = time(NULL);
			/* 2 seconds is minimum normal timeout */
			if ((curtime - prevtime) >= 2) {
				nat_cleaning();
				prevtime = curtime;
			}
			i = 0;
		}
	}

	/* unset the promiscuous mode */
	if (setsockopt(sniff_sock, SOL_PACKET, PACKET_DROP_MEMBERSHIP,
	    (char *) &pmr, sizeof(pmr)) == -1) {
		perror("setsockopt PACKET_DROP_MEMBERSHIP");
		log_error("IPv4: Unable to unset the promiscuous mode on the "
			  "interface %s", interface_ipv4.ifr_name);
		/* do not call return here as we want to close the socket too */
	}

	/* close the socket */
	close(sniff_sock);

	pthread_exit(NULL);

	return NULL;
}

/**
 * Decide what to do with a packet and pass it for further processing.
 *
 * @param	packet	Packet data
 * @param	length	Packet data length
 * @param	is_ipv6	Interface type
 *
 * @return	0 for success
 * @return	1 for failure
 */
static int process(unsigned char *packet, unsigned short length, int is_ipv6)
{
	struct s_ethernet *eth;

	/* sanity check: out of every combination this is the smallest one */
	if (!is_ipv6 && (length < sizeof(struct s_ethernet) +
				  sizeof(struct s_ipv4) +
				  sizeof(struct s_icmp))) {
		log_warn("IPv4: bad packet [length:%u]", length);
		return 1;
	}

#if 1
	/* HACK: For 6lowpan traffic the L2 info header doesn't exist: add it manually */

	/*
	 * NOTE: This could be Neighbor Advertisement or Router Advertisement as well.
	 * These types of packets will fail silently with the IP address doesn't match
	 * in ipv6()
	 */
	if (is_ipv6 && *(unsigned int *)packet == 0x00000060) {
		struct s_ethernet eth6;
		size_t eth6_len;

		log_info("HACK: missing eth hdr");
		/* build ethernet header */
		eth6_len = sizeof(eth6);
		eth6.dest = mac_ipv6;
		eth6.src  = mac_ipv6;
		eth6.type = htons(ETHERTYPE_IPV6);

		memmove(packet + eth6_len, packet, eth6_len);
		memcpy(packet, &eth6, eth6_len);
		length += eth6_len;
	}
#endif

	/* sanity check: out of every combination this is the smallest one */
	if (is_ipv6 && (length < sizeof(struct s_ethernet) +
				 sizeof(struct s_ipv6) +
				 sizeof(struct s_icmp))) {
		log_warn("IPv6: bad packet [length:%u]", length);
		return 1;
	}

	/* parse ethernet header */
	eth = (struct s_ethernet *) packet;

	#define payload		packet + sizeof(struct s_ethernet)
	#define payload_length	length - sizeof(struct s_ethernet)

	switch (htons(eth->type)) {
		case ETHERTYPE_IP:
			if (is_ipv6) {
				return 1;
			}
			else {
				return ipv4(eth, payload, payload_length);
			}
		case ETHERTYPE_IPV6:
			if (!is_ipv6) {
				return 1;
			}
			else {
				return ipv6(eth, payload, payload_length);
			}
		case ETHERTYPE_ARP:
			return arp(eth, payload, payload_length);
		default:
			log_debug("HW Protocol: unknown [%d/0x%04x]",
			       htons(eth->type), htons(eth->type));
			return 1;
	}

	#undef payload_length
	#undef payload
}

/**
 * Translator of IPv6 address with embedded IPv4 address to that IPv4 address.
 *
 * @param	ipv6_addr	IPv6 address (as data source)
 * @param	ipv4_addr	Where to put final IPv4 address
 */
void ipv6_to_ipv4(struct s_ipv6_addr *ipv6_addr, struct s_ipv4_addr *ipv4_addr)
{
	memcpy(ipv4_addr, ipv6_addr->addr + 12, 4);
}

/**
 * Translator of IPv4 address to IPv6 address with WrapSix' prefix.
 *
 * @param	ipv4_addr	IPv4 address (as data source)
 * @param	ipv6_addr	Where to put final IPv6 address
 */
void ipv4_to_ipv6(struct s_ipv4_addr *ipv4_addr, struct s_ipv6_addr *ipv6_addr)
{
	memcpy(ipv6_addr, &wrapsix_ipv6_prefix, 12);
	memcpy(ipv6_addr->addr + 12, ipv4_addr, 4);
}
