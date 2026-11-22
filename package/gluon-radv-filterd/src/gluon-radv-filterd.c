/* SPDX-FileCopyrightText: 2016 Jan-Philipp Litza <janphilipp@litza.de> */
/* SPDX-FileCopyrightText: 2017 Sven Eckelmann <sven@narfation.org> */
/* SPDX-License-Identifier: BSD-2-Clause */

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <net/ethernet.h>
#include <net/if.h>

#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/limits.h>

#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include <arpa/inet.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <batadv-genl.h>

#include "mac.h"

// Recheck metrics after this time even if no RA was received
#define MAX_INTERVAL 60

// Recheck metrics at most this often, even if new RAs were received (they won't
// become the preferred routers until the metrics have been rechecked)
// Also, the first update will take at least this long
#define MIN_INTERVAL 15
// Rebuild the redirect chains after this time even if nothing changed. The check
// only runs every MIN_INTERVAL, so the chains are restored within 60 seconds at
// the latest.
#define REDIRECT_RESYNC_INTERVAL 45

// Remember the originator of a router for at most this period of time (in
// seconds). Re-read it from the transtable afterwards.
#define ORIGINATOR_CACHE_TTL 300

// max execution time of a single ebtables call in nanoseconds
#define EBTABLES_TIMEOUT 500000000 // 500ms

// BATMAN IV TQ values are 0-255; reject larger thresholds since
// it would silently prevent the gateway from switching.
#define BATMAN_IV_MAX_THRESHOLD 255

#define BUFSIZE 1500

#ifdef DEBUG
#define CHECK(stmt) \
	if(!(stmt)) { \
		fprintf(stderr, "check failed: " #stmt "\n"); \
		goto check_failed; \
	}
#define DEBUG_MSG(msg, ...) fprintf(stderr, msg "\n", ##__VA_ARGS__)
#else
#define CHECK(stmt) if(!(stmt)) goto check_failed;
#define DEBUG_MSG(msg, ...) do {} while(0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(A) (sizeof(A)/sizeof(A[0]))
#endif

#define foreach(item, list) \
	for((item) = (list); (item) != NULL; (item) = (item)->next)

#define foreach_safe(item, safe, list) \
	for ((item) = (list); \
			(item) && (((safe) = item->next) || 1); \
			(item) = (safe))

struct router {
	struct router *next;
	struct ether_addr src;
	struct timespec eol;
	struct ether_addr originator;
	uint32_t metric;
	bool has_prefix;
	struct in6_addr prefix;
};

static struct global {
	int sock;
	unsigned int ifindex;
	struct router *routers;
	const char *mesh_iface;
	const char *chain;
	/* redirect IPv6 packets to the router owning the source prefix */
	bool redirect;
	/* signature of the router/prefix set the redirect chains were built
	 * for, and the time of the last rebuild */
	uint64_t redirect_sig;
	struct timespec redirect_synced;
	bool redirect_dirty;
	uint32_t max_metric;
	uint32_t hysteresis_thresh;
	struct router *best_router;
	enum batadv_algo algo;
	volatile sig_atomic_t stop_daemon;
} G = {
	.mesh_iface = "bat0",
};

static int fork_execvp_timeout(struct timespec *timeout, const char *file,
		const char *const argv[]);

static void error_message(int status, int errnum, char *message, ...) {
	va_list ap;
	va_start(ap, message);
	fflush(stdout);
	vfprintf(stderr, message, ap);
	va_end(ap);

	if (errnum)
		fprintf(stderr, ": %s", strerror(errnum));
	fprintf(stderr, "\n");
	if (status)
		exit(status);
}

static int timespec_diff(struct timespec *tv1, struct timespec *tv2,
		struct timespec *tvdiff)
{
	tvdiff->tv_sec = tv1->tv_sec - tv2->tv_sec;
	if (tv1->tv_nsec < tv2->tv_nsec) {
		tvdiff->tv_nsec = 1000000000 + tv1->tv_nsec - tv2->tv_nsec;
		tvdiff->tv_sec -= 1;
	} else {
		tvdiff->tv_nsec = tv1->tv_nsec - tv2->tv_nsec;
	}

	return (tvdiff->tv_sec >= 0);
}

static void cleanup(void) {
	struct router *router;
	struct timespec timeout = {
		.tv_nsec = EBTABLES_TIMEOUT,
	};

	close(G.sock);

	while (G.routers != NULL) {
		router = G.routers;
		G.routers = router->next;
		free(router);
	}

	if (G.chain) {
		/* Reset chain to accept everything again */
		if (fork_execvp_timeout(&timeout, "ebtables-tiny", (const char *[])
				{ "ebtables-tiny", "-F", G.chain, NULL }))
			DEBUG_MSG("warning: flushing ebtables chain %s failed, not adding a new rule", G.chain);

		if (fork_execvp_timeout(&timeout, "ebtables-tiny", (const char *[])
				{ "ebtables-tiny", "-A", G.chain, "-j", "ACCEPT", NULL }))
			DEBUG_MSG("warning: adding new rule to ebtables chain %s failed", G.chain);
	}

	if (G.redirect) {
		if (fork_execvp_timeout(&timeout, "ebtables-tiny", (const char *[])
				{ "ebtables-tiny", "-t", "nat", "-F", "REDIRECT_FILTER", NULL}))
			DEBUG_MSG("warning: flushing ebtables nat chain REDIRECT_FILTER failed");

		if (fork_execvp_timeout(&timeout, "ebtables-tiny", (const char *[])
				{ "ebtables-tiny", "-t", "nat", "-F", "REDIRECT", NULL}))
			DEBUG_MSG("warning: flushing ebtables nat chain REDIRECT failed");
	}
}

static void usage(const char *msg) {
	if (msg != NULL && *msg != '\0') {
		fprintf(stderr, "ERROR: %s\n\n", msg);
	}
	fprintf(stderr,
		"Usage: %s [-m <mesh_iface>] [-r] [-t <thresh>] -c <chain> -i <iface>\n\n"
		"  -m <mesh_iface>  B.A.T.M.A.N. advanced mesh interface used to get metric\n"
		"                   information (TQ or throughput) for the available gateways.\n"
		"                   Default: bat0\n"
		"  -r               Redirect IPv6 packets to the router whose advertised prefix\n"
		"                   matches their source address. Requires the ebtables nat\n"
		"                   chains REDIRECT_FILTER and REDIRECT to exist and will\n"
		"                   flush them. Only useful if routers announce different\n"
		"                   prefixes on the same link.\n"
		"  -t <thresh>      Minimum metric difference required to switch the gateway.\n"
		"                   The unit depends on the routing algorithm in use:\n"
		"                     BATMAN_IV: TQ points, 0-255   (e.g. 20 ~ 8%% of max)\n"
		"                     BATMAN_V:  throughput, kbit/s (e.g. 50000 ~ 50 Mbit/s)\n"
		"                   0 selects the best gateway without any hysteresis.\n"
		"                   Default: 0\n"
		"  -c <chain>       ebtables chain that should be managed by the daemon. The\n"
		"                   chain already has to exist on program invocation and should\n"
		"                   have a DROP policy. It will be flushed by the program!\n"
		"  -i <iface>       Interface to listen on for router advertisements. Should be\n"
		"                   <mesh_iface> or a bridge on top of it, as no metric\n"
		"                   information will be available for hosts on other interfaces.\n\n",
		program_invocation_short_name);
	cleanup();
	if (msg == NULL)
		exit(EXIT_SUCCESS);
	else
		exit(EXIT_FAILURE);
}

#define exit_errmsg(message, ...) { \
	fprintf(stderr, message "\n", ##__VA_ARGS__); \
	cleanup(); \
	exit(1); \
	}

static inline void exit_errno(const char *message) {
	cleanup();
	error_message(1, errno, "error: %s", message);
}

static inline void warn_errno(const char *message) {
	error_message(0, errno, "warning: %s", message);
}

static int init_packet_socket(unsigned int ifindex) {
	struct sock_filter radv_filter_code[] = {
		// the socket may receive all protocols, check that this is an IPv6 packet
		BPF_STMT(BPF_LD|BPF_H|BPF_ABS, SKF_AD_OFF + SKF_AD_PROTOCOL),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ETH_P_IPV6, 0, 9),
		// check that this is an ICMPv6 packet
		BPF_STMT(BPF_LD|BPF_B|BPF_ABS, offsetof(struct ip6_hdr, ip6_nxt)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_ICMPV6, 0, 7),
		// check that this is a router advertisement
		BPF_STMT(BPF_LD|BPF_B|BPF_ABS, sizeof(struct ip6_hdr) + offsetof(struct icmp6_hdr, icmp6_type)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ND_ROUTER_ADVERT, 0, 5),
		// check that the code field in the ICMPv6 header is 0
		BPF_STMT(BPF_LD|BPF_B|BPF_ABS, sizeof(struct ip6_hdr) + offsetof(struct nd_router_advert, nd_ra_code)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 0, 3),
		// check that this is a default route (lifetime > 0)
		BPF_STMT(BPF_LD|BPF_H|BPF_ABS, sizeof(struct ip6_hdr) + offsetof(struct nd_router_advert, nd_ra_router_lifetime)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 1, 0),
		// return true
		BPF_STMT(BPF_RET|BPF_K, 0xffffffff),
		// return false
		BPF_STMT(BPF_RET|BPF_K, 0),
	};

	struct sock_fprog radv_filter = {
		.len = ARRAY_SIZE(radv_filter_code),
		.filter = radv_filter_code,
	};

	int sock = socket(AF_PACKET, SOCK_DGRAM|SOCK_CLOEXEC, htons(ETH_P_IPV6));
	if (sock < 0)
		exit_errno("can't open packet socket");
	int ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &radv_filter, sizeof(radv_filter));
	if (ret < 0)
		exit_errno("can't attach socket filter");

	struct sockaddr_ll bind_iface = {
		.sll_family = AF_PACKET,
		/* the redirect needs to see the node's own RAs (PACKET_OUTGOING) too,
		 * which are only delivered to sockets bound to ETH_P_ALL */
		.sll_protocol = htons(G.redirect ? ETH_P_ALL : ETH_P_IPV6),
		.sll_ifindex = ifindex,
	};
	ret = bind(sock, (struct sockaddr *)&bind_iface, sizeof(bind_iface));
	if (ret < 0)
		exit_errno("can't bind socket");

	return sock;
}

static void parse_cmdline(int argc, char *argv[]) {
	int c;
	unsigned long int threshold;
	char *endptr;
	while ((c = getopt(argc, argv, "c:hi:m:rt:")) != -1) {
		switch (c) {
			case 'r':
				G.redirect = true;
				break;
			case 'i':
				if (G.ifindex != 0)
					usage("-i given more than once");
				G.ifindex = if_nametoindex(optarg);
				if (G.ifindex == 0)
					exit_errmsg("Unknown interface: %s", optarg);
				break;
			case 'm':
				G.mesh_iface = optarg;
				break;
			case 'c':
				G.chain = optarg;
				break;
			case 't':
				threshold = strtoul(optarg, &endptr, 10);
				if (*endptr != '\0')
					exit_errmsg("Threshold must be a number: %s", optarg);
				G.hysteresis_thresh = (uint32_t) threshold;
				break;
			case 'h':
				usage(NULL);
				break;
			default:
				usage("");
				break;
		}
	}
}

static struct router *router_find_src(const struct ether_addr *src) {
	struct router *router;

	foreach(router, G.routers) {
		if (ether_addr_equal(router->src, *src))
			return router;
	}

	return NULL;
}

static struct router *router_find_orig(const struct ether_addr *orig) {
	struct router *router;

	foreach(router, G.routers) {
		if (ether_addr_equal(router->originator, *orig))
			return router;
	}

	return NULL;
}

static struct router *router_add(const struct ether_addr *mac) {
	struct router *router;

	router = calloc(1, sizeof(*router));
	if (!router)
		return NULL;

	router->src = *mac;
	router->next = G.routers;
	G.routers = router;

	return router;
}

/* Find the first prefix information option announcing a /64 prefix. The
 * options are untrusted data from the mesh.
 */
static bool find_prefix(const uint8_t *ptr, size_t len, struct in6_addr *prefix) {
	while (len >= 8) {
		size_t o_len = (size_t)ptr[1] << 3;

		// a zero length is invalid and would never advance
		if (o_len == 0 || o_len > len)
			return false;

		if (ptr[0] == ND_OPT_PREFIX_INFORMATION) {
			const struct nd_opt_prefix_info *o_pi = (const struct nd_opt_prefix_info *)ptr;

			if (o_len < sizeof(*o_pi))
				return false;

			if (o_pi->nd_opt_pi_prefix_len == 64) {
				// only keep the /64, ignore host bits
				memset(prefix, 0, sizeof(*prefix));
				memcpy(prefix, &o_pi->nd_opt_pi_prefix, 8);
				return true;
			}
		}

		ptr += o_len;
		len -= o_len;
	}

	return false;
}

static struct router *router_update(const struct ether_addr *mac, uint16_t timeout) {
	struct router *router;

	router = router_find_src(mac);
	if (!router)
		router = router_add(mac);
	if (!router)
		return NULL;

	clock_gettime(CLOCK_MONOTONIC, &router->eol);
	router->eol.tv_sec += timeout;

	return router;
}

static void handle_ra(int sock) {
	struct sockaddr_ll src;
	struct ether_addr mac;
	socklen_t addr_size = sizeof(src);
	ssize_t len;
	size_t pkt_len;
	struct {
		struct {
			struct ip6_hdr ip6;
			struct nd_router_advert ra;
		} hdr;
		uint8_t options[128];
	} pkt;
	struct router *router;
	struct in6_addr prefix;
	char addr_str[INET6_ADDRSTRLEN];

	len = recvfrom(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&src, &addr_size);
	CHECK(len >= 0);

	// BPF already checked that this is an ICMPv6 RA of a default router
	CHECK((size_t)len >= sizeof(pkt.hdr));
	CHECK(ntohs(pkt.hdr.ip6.ip6_plen) + sizeof(struct ip6_hdr) >= sizeof(pkt.hdr));

	memcpy(&mac, src.sll_addr, sizeof(mac));
	DEBUG_MSG("received valid RA from " F_MAC, F_MAC_VAR(mac));

	router = router_update(&mac, ntohs(pkt.hdr.ra.nd_ra_router_lifetime));
	if (!router || !G.redirect)
		return;

	// the options end at the end of the received data or the IPv6 payload
	pkt_len = ntohs(pkt.hdr.ip6.ip6_plen) + sizeof(struct ip6_hdr);
	if (pkt_len > (size_t)len)
		pkt_len = len;

	if (find_prefix(pkt.options, pkt_len - sizeof(pkt.hdr), &prefix)) {
		router->prefix = prefix;
		router->has_prefix = true;

		CHECK(inet_ntop(AF_INET6, &router->prefix, addr_str, sizeof(addr_str)));
		DEBUG_MSG("prefix: %s", addr_str);
	}

check_failed:
	return;
}

static void expire_routers(void) {
	struct router **prev_ptr = &G.routers;
	struct router *router;
	struct router *safe;
	struct timespec now;
	struct timespec diff;

	clock_gettime(CLOCK_MONOTONIC, &now);

	foreach_safe(router, safe, G.routers) {
		if (timespec_diff(&now, &router->eol, &diff)) {
			DEBUG_MSG("router " F_MAC " expired", F_MAC_VAR(router->src));
			*prev_ptr = router->next;
			if (G.best_router == router)
				G.best_router = NULL;
			free(router);
		} else {
			prev_ptr = &router->next;
		}
	}
}

static int parse_tt_global(struct nl_msg *msg,
		void *arg __attribute__((unused)))
{
	static const enum batadv_nl_attrs mandatory[] = {
		BATADV_ATTR_TT_ADDRESS,
		BATADV_ATTR_ORIG_ADDRESS,
	};
	struct nlattr *attrs[BATADV_ATTR_MAX + 1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct ether_addr mac_a, mac_b;
	struct genlmsghdr *ghdr;
	struct router *router;
	uint8_t *addr;
	uint8_t *orig;

	// parse netlink entry
	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_TRANSTABLE_GLOBAL)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
				genlmsg_len(ghdr), batadv_genl_policy)) {
		return NL_OK;
	}

	if (batadv_genl_missing_attrs(attrs, mandatory, ARRAY_SIZE(mandatory)))
		return NL_OK;

	addr = nla_data(attrs[BATADV_ATTR_TT_ADDRESS]);
	orig = nla_data(attrs[BATADV_ATTR_ORIG_ADDRESS]);

	if (!attrs[BATADV_ATTR_FLAG_BEST])
		return NL_OK;

	MAC2ETHER(mac_a, addr);
	MAC2ETHER(mac_b, orig);

	// update router
	router = router_find_src(&mac_a);
	if (!router)
		return NL_OK;

	DEBUG_MSG("Found originator for " F_MAC ", it's " F_MAC,
			F_MAC_VAR(router->src), F_MAC_VAR(mac_b));
	router->originator = mac_b;

	return NL_OK;
}

static const enum batadv_nl_attrs originator_mandatory_batadv_iv[] = {
	BATADV_ATTR_ORIG_ADDRESS,
	BATADV_ATTR_TQ,
};

static const enum batadv_nl_attrs originator_mandatory_batadv_v[] = {
	BATADV_ATTR_ORIG_ADDRESS,
	BATADV_ATTR_THROUGHPUT,
};

static int parse_originator(struct nl_msg *msg,
		void *arg __attribute__((unused)))
{
	struct nlattr *attrs[BATADV_ATTR_MAX + 1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct ether_addr mac_a;
	struct genlmsghdr *ghdr;
	struct router *router;
	uint8_t *orig;
	uint32_t metric;

	// parse netlink entry
	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_ORIGINATORS)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
				genlmsg_len(ghdr), batadv_genl_policy)) {
		return NL_OK;
	}

	if (G.algo == BATADV_ALGO_BATMAN_V) {
		if (batadv_genl_missing_attrs(attrs, originator_mandatory_batadv_v,
					ARRAY_SIZE(originator_mandatory_batadv_v)))
			return NL_OK;
	} else {
		if (batadv_genl_missing_attrs(attrs, originator_mandatory_batadv_iv,
					ARRAY_SIZE(originator_mandatory_batadv_iv)))
			return NL_OK;
	}

	if (!attrs[BATADV_ATTR_FLAG_BEST])
		return NL_OK;

	orig = nla_data(attrs[BATADV_ATTR_ORIG_ADDRESS]);
	metric = (G.algo == BATADV_ALGO_BATMAN_V)
		? nla_get_u32(attrs[BATADV_ATTR_THROUGHPUT])
		: nla_get_u8(attrs[BATADV_ATTR_TQ]);

	MAC2ETHER(mac_a, orig);

	// update router
	router = router_find_orig(&mac_a);
	if (!router)
		return NL_OK;

	DEBUG_MSG("Found metric for router " F_MAC " (originator " F_MAC "), it's %u",
			F_MAC_VAR(router->src), F_MAC_VAR(router->originator), metric);
	router->metric = metric;
	if (router->metric > G.max_metric)
		G.max_metric = router->metric;

	return NL_OK;
}

static int parse_tt_local(struct nl_msg *msg,
		void *arg __attribute__((unused)))
{
	static const enum batadv_nl_attrs mandatory[] = {
		BATADV_ATTR_TT_ADDRESS,
	};
	struct nlattr *attrs[BATADV_ATTR_MAX + 1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct ether_addr mac_a;
	struct genlmsghdr *ghdr;
	struct router *router;
	uint8_t *addr;

	// parse netlink entry
	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_TRANSTABLE_LOCAL)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
				genlmsg_len(ghdr), batadv_genl_policy)) {
		return NL_OK;
	}

	if (batadv_genl_missing_attrs(attrs, mandatory, ARRAY_SIZE(mandatory)))
		return NL_OK;

	addr = nla_data(attrs[BATADV_ATTR_TT_ADDRESS]);
	MAC2ETHER(mac_a, addr);

	// update router
	router = router_find_src(&mac_a);
	if (!router)
		return NL_OK;

	router->metric = UINT32_MAX;
	DEBUG_MSG("Found router " F_MAC " in transtable_local, assigning metric %u",
			F_MAC_VAR(router->src), router->metric);
	if (router->metric > G.max_metric)
		G.max_metric = router->metric;

	return NL_OK;
}

static void update_metrics(void) {
	static const struct ether_addr unspec = {};
	struct router *router;
	bool update_originators = false;
	struct batadv_nlquery_opts opts;
	int ret;

	// reset metrics
	foreach(router, G.routers) {
		router->metric = 0;
		if (ether_addr_equal(router->originator, unspec))
			update_originators = true;
	}

	// translate all router's MAC addresses to originators simultaneously
	if (update_originators) {
		opts.err = 0;
		ret = batadv_genl_query(G.mesh_iface,
					BATADV_CMD_GET_TRANSTABLE_GLOBAL,
					parse_tt_global, NLM_F_DUMP, &opts);
		if (ret < 0)
			fprintf(stderr, "Parsing of global translation table failed\n");
	}

	// look up metrics of originators
	G.max_metric = 0;
	opts.err = 0;
	ret = batadv_genl_query(G.mesh_iface,
				BATADV_CMD_GET_ORIGINATORS,
				parse_originator, NLM_F_DUMP, &opts);
	if (ret < 0)
		fprintf(stderr, "Parsing of originators failed\n");

	// if all routers have a metric value, we don't need to check translocal
	foreach(router, G.routers) {
		if (router->metric == 0)
			break;
	}
	if (router != NULL) {
		opts.err = 0;
		ret = batadv_genl_query(G.mesh_iface,
					BATADV_CMD_GET_TRANSTABLE_LOCAL,
					parse_tt_local, NLM_F_DUMP, &opts);
		if (ret < 0)
			fprintf(stderr, "Parsing of local translation table failed\n");
	}

	foreach(router, G.routers) {
		if (router->metric == 0) {
			if (ether_addr_equal(router->originator, unspec))
				DEBUG_MSG(
					"Unable to find router " F_MAC " in transtable_{global,local}",
					F_MAC_VAR(router->src));
			else
				DEBUG_MSG(
					"Unable to find metric for originator " F_MAC " (router " F_MAC ")",
					F_MAC_VAR(router->originator),
					F_MAC_VAR(router->src));
		}
	}
}

static uint64_t redirect_signature(void) {
	struct router *router;
	uint64_t sig = 14695981039346656037ULL;
	const uint8_t *p;
	size_t i;

	foreach(router, G.routers) {
		if (!router->has_prefix)
			continue;

		p = (const uint8_t *)&router->src;
		for (i = 0; i < sizeof(router->src); i++)
			sig = (sig ^ p[i]) * 1099511628211ULL;

		p = (const uint8_t *)&router->prefix;
		for (i = 0; i < sizeof(router->prefix); i++)
			sig = (sig ^ p[i]) * 1099511628211ULL;
	}

	return sig;
}

/* Rebuild the redirect chains from scratch. Other components (gluon-ebtables)
 * re-create the nat chains behind our back, and rules of expired routers or
 * changed prefixes have to go, so the state is never patched incrementally. */
static void update_redirect(void) {
	struct router *router;
	struct timespec now, diff;
	struct timespec timeout = {
		.tv_nsec = EBTABLES_TIMEOUT,
	};
	uint64_t sig = redirect_signature();

	clock_gettime(CLOCK_MONOTONIC, &now);

	if (!G.redirect_dirty && sig == G.redirect_sig &&
			!timespec_diff(&now, &G.redirect_synced, &diff))
		return;

	// a failure below leaves the dirty flag set, the next update retries
	G.redirect_dirty = true;

	if (fork_execvp_timeout(&timeout, "ebtables-tiny", (const char *[])
			{ "ebtables-tiny", "-t", "nat", "-F", "REDIRECT_FILTER", NULL})) {
		error_message(0, 0, "warning: flushing ebtables nat chain REDIRECT_FILTER failed");
		return;
	}

	if (fork_execvp_timeout(&timeout, "ebtables-tiny", (const char *[])
			{ "ebtables-tiny", "-t", "nat", "-F", "REDIRECT", NULL})) {
		error_message(0, 0, "warning: flushing ebtables nat chain REDIRECT failed");
		return;
	}

	G.redirect_dirty = false;

	foreach(router, G.routers) {
		char mac[F_MAC_LEN + 1];
		char addr[INET6_ADDRSTRLEN];
		char prefix[INET6_ADDRSTRLEN + 3];

		if (!router->has_prefix)
			continue;

		snprintf(mac, sizeof(mac), F_MAC, F_MAC_VAR(router->src));

		if (inet_ntop(AF_INET6, &router->prefix, addr, sizeof(addr)) == NULL) {
			error_message(0, 0, "warning: failed to format prefix");
			continue;
		}
		snprintf(prefix, sizeof(prefix), "%s/64", addr);

		if (fork_execvp_timeout(&timeout, "ebtables-tiny", (const char *[])
			{ "ebtables-tiny", "-t", "nat", "-A", "REDIRECT",
			"-p", "IPv6",
			"--ip6-source", prefix,
			"--ip6-destination", "!", prefix,
			"-d", "!",  mac,
			"-j", "dnat",
			"--to-destination", mac,
			NULL })) {
			error_message(0, 0, "warning: adding new rule to ebtables chain REDIRECT failed");
			G.redirect_dirty = true;
			continue;
		}

		if (fork_execvp_timeout(&timeout, "ebtables-tiny", (const char *[])
			{ "ebtables-tiny", "-t", "nat", "-A", "REDIRECT_FILTER",
			"-d", mac,
			"-j", "REDIRECT",
			NULL })) {
			error_message(0, 0, "warning: adding new rule to ebtables chain REDIRECT_FILTER failed");
			G.redirect_dirty = true;
		}
	}

	G.redirect_sig = sig;
	G.redirect_synced = now;
	G.redirect_synced.tv_sec += REDIRECT_RESYNC_INTERVAL;
}

static int fork_execvp_timeout(struct timespec *timeout, const char *file, const char *const argv[]) {
	int ret;
	pid_t child;
	siginfo_t info;
	sigset_t signals, oldsignals;
	sigemptyset(&signals);
	sigaddset(&signals, SIGCHLD);

	sigprocmask(SIG_BLOCK, &signals, &oldsignals);
	child = fork();
	if (child == 0) {
		sigprocmask(SIG_SETMASK, &oldsignals, NULL);
		// casting discards const, but should be safe
		// (see https://stackoverflow.com/q/36925388)
		execvp(file, (char**) argv);
		fprintf(stderr, "can't execvp(\"%s\", ...): %s\n", file, strerror(errno));
		_exit(1);
	}
	else if (child < 0) {
		perror("Failed to fork()");
		return -1;
	}

	ret = sigtimedwait(&signals, &info, timeout);
	sigprocmask(SIG_SETMASK, &oldsignals, NULL);

	if (ret == SIGCHLD) {
		if (info.si_pid != child) {
			cleanup();
			error_message(1, 0,
				"BUG: We received a SIGCHLD from a child we didn't spawn (expected PID %d, got %d)",
				child, info.si_pid);
		}

		waitpid(child, NULL, 0);

		return info.si_status;
	}

	if (ret < 0 && errno == EAGAIN)
		error_message(0, 0, "warning: child %d took too long, killing", child);
	else if (ret < 0)
		warn_errno("sigtimedwait failed, killing child");
	else
		error_message(1, 0,
				"BUG: sigtimedwait() returned some other signal than SIGCHLD: %d",
				ret);

	kill(child, SIGKILL);
	kill(child, SIGCONT);
	waitpid(child, NULL, 0);
	return -1;
}

static bool election_required(void)
{
	if (!G.best_router)
		return true;

	/* should never happen. G.max_metric also contains G.best_router->metric */
	if (G.max_metric < G.best_router->metric)
		return false;

	if ((G.max_metric - G.best_router->metric) <= G.hysteresis_thresh)
		return false;

	return true;
}

static void update_ebtables(void) {
	struct timespec timeout = {
		.tv_nsec = EBTABLES_TIMEOUT,
	};
	char mac[F_MAC_LEN + 1];
	struct router *router;

	if (!election_required()) {
		DEBUG_MSG(F_MAC " is still good enough with metric=%u (max_metric=%u), not executing ebtables",
			F_MAC_VAR(G.best_router->src),
			G.best_router->metric,
			G.max_metric);
		return;
	}

	foreach(router, G.routers) {
		if (router->metric == G.max_metric) {
			snprintf(mac, sizeof(mac), F_MAC, F_MAC_VAR(router->src));
			break;
		}
	}
	if (G.best_router)
		fprintf(stderr, "Switching from " F_MAC " (metric=%u) to %s (metric=%u)\n",
			F_MAC_VAR(G.best_router->src),
			G.best_router->metric,
			mac,
			G.max_metric);
	else
		fprintf(stderr, "Switching to %s (metric=%u)\n",
			mac,
			G.max_metric);
	G.best_router = router;

	if (fork_execvp_timeout(&timeout, "ebtables-tiny", (const char *[])
			{ "ebtables-tiny", "-F", G.chain, NULL }))
		error_message(0, 0, "warning: flushing ebtables chain %s failed, not adding a new rule", G.chain);
	else if (fork_execvp_timeout(&timeout, "ebtables-tiny", (const char *[])
			{ "ebtables-tiny", "-A", G.chain, "-s", mac, "-j", "ACCEPT", NULL }))
		error_message(0, 0, "warning: adding new rule to ebtables chain %s failed", G.chain);
}

static void invalidate_originators(void)
{
	struct router *router;
	foreach(router, G.routers) {
		memset(&router->originator, 0, sizeof(router->originator));
	}
}

static void sighandler(int sig __attribute__((unused)))
{
	G.stop_daemon = 1;
}

int main(int argc, char *argv[]) {
	int retval;
	fd_set rfds;
	struct timeval tv;
	struct timespec next_update;
	struct timespec next_invalidation;
	struct timespec now;
	struct timespec diff;

	clock_gettime(CLOCK_MONOTONIC, &next_update);
	next_update.tv_sec += MIN_INTERVAL;

	clock_gettime(CLOCK_MONOTONIC, &next_invalidation);
	next_invalidation.tv_sec += MIN_INTERVAL;

	G.sock = -1;
	parse_cmdline(argc, argv);

	if (G.ifindex == 0)
		usage("No interface set!");

	if (G.chain == NULL)
		usage("No chain set!");

	// needs to come after parse_cmdline(): the bind depends on -r
	G.sock = init_packet_socket(G.ifindex);

	if (batadv_genl_get_algo(G.mesh_iface, &G.algo) < 0)
		exit_errmsg("Failed to detect batman-adv routing algorithm on %s", G.mesh_iface);

	fprintf(stderr, "Using batman-adv algorithm: %s\n",
		G.algo == BATADV_ALGO_BATMAN_V ? "BATMAN_V" : "BATMAN_IV");

	if (G.algo == BATADV_ALGO_BATMAN_IV && G.hysteresis_thresh > BATMAN_IV_MAX_THRESHOLD)
		exit_errmsg("Threshold too large: %u (max is %u)",
			G.hysteresis_thresh, BATMAN_IV_MAX_THRESHOLD);

	G.stop_daemon = 0;
	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	while (!G.stop_daemon) {
		FD_ZERO(&rfds);
		FD_SET(G.sock, &rfds);

		tv.tv_sec = MAX_INTERVAL;
		tv.tv_usec = 0;
		retval = select(G.sock + 1, &rfds, NULL, NULL, &tv);

		if (retval < 0) {
			if (errno != EINTR)
				exit_errno("select() failed");
		} else if (retval) {
			if (FD_ISSET(G.sock, &rfds)) {
				handle_ra(G.sock);
			}
		}
		else
			DEBUG_MSG("select() timeout expired");

		clock_gettime(CLOCK_MONOTONIC, &now);
		if (G.routers != NULL &&
				timespec_diff(&now, &next_update, &diff)) {
			expire_routers();

			// the redirect rules follow the router list, which may have shrunk
			if (G.redirect)
				update_redirect();

			// all routers could have expired, check again
			if (G.routers != NULL) {
				if(timespec_diff(&now, &next_invalidation, &diff)) {
					invalidate_originators();

					next_invalidation = now;
					next_invalidation.tv_sec += ORIGINATOR_CACHE_TTL;
				}

				update_metrics();
				update_ebtables();

				next_update = now;
				next_update.tv_sec += MIN_INTERVAL;
			}
		} else if (G.routers == NULL && G.redirect) {
			// no router left: flush stale redirect rules once and keep
			// resyncing them
			update_redirect();
		}
	}

	cleanup();
	return 0;
}
