/* 
 * Fluffy Funicular Listener (random naming thanks to github)
 * Copyright 2018, Andy Gospodarek
 * SPDX-License-Identifier: GPL-2.0
 *
 * A great deal of this code is inherited from iproute2:
 * 	git://git.kernel.org/pub/scm/linux/kernel/git/shemminger/iproute2.git
 *
 * libnl would have probably been quicker/smaller LoC, but I wanted this as
 * standalone as possible.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <errno.h>

int rcvbuf = 1024 * 1024;
extern struct rtnl_handle rth;
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

struct rtnl_handle {
    int fd;
    struct sockaddr_nl local;
    struct sockaddr_nl peer;
    __u32 seq;
    __u32 dump;
    int proto;
    FILE *dump_fp;
#define RTNL_HANDLE_F_LISTEN_ALL_NSID           0x01
#define RTNL_HANDLE_F_SUPPRESS_NLERR            0x02
    int flags;
};

struct iplink_req {
    struct nlmsghdr n;
    struct ifinfomsg i;
    char buf[1024];
};

#define NLMSG_TAIL(nmsg) \
        ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))


int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
	      int alen)
{
    int len = RTA_LENGTH(alen);
    struct rtattr *rta;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
	fprintf(stderr,
		"addattr_l ERROR: message exceeded bound of %d\n", maxlen);
	return -1;
    }
    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = len;
    if (alen)
	memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    return 0;
}

struct rtattr *addattr_nest(struct nlmsghdr *n, int maxlen, int type)
{
    struct rtattr *nest = NLMSG_TAIL(n);

    addattr_l(n, maxlen, type, NULL, 0);
    return nest;
}

int addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
    nest->rta_len = (void *) NLMSG_TAIL(n) - (void *) nest;
    return n->nlmsg_len;
}

int addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data)
{
    return addattr_l(n, maxlen, type, &data, sizeof(__u32));
}

int rtnl_open_byproto(struct rtnl_handle *rth, unsigned int subscriptions,
		      int protocol)
{
    socklen_t addr_len;
    int sndbuf = 32768;
    int one = 1;

    memset(rth, 0, sizeof(*rth));

    rth->proto = protocol;
    rth->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol);
    if (rth->fd < 0) {
	perror("Cannot open netlink socket");
	return -1;
    }

    if (setsockopt(rth->fd, SOL_SOCKET, SO_SNDBUF,
		   &sndbuf, sizeof(sndbuf)) < 0) {
	perror("SO_SNDBUF");
	return -1;
    }

    if (setsockopt(rth->fd, SOL_SOCKET, SO_RCVBUF,
		   &rcvbuf, sizeof(rcvbuf)) < 0) {
	perror("SO_RCVBUF");
	return -1;
    }

    memset(&rth->local, 0, sizeof(rth->local));
    rth->local.nl_family = AF_NETLINK;
    rth->local.nl_groups = subscriptions;

    if (bind(rth->fd, (struct sockaddr *) &rth->local,
	     sizeof(rth->local)) < 0) {
	perror("Cannot bind netlink socket");
	return -1;
    }
    addr_len = sizeof(rth->local);
    if (getsockname(rth->fd, (struct sockaddr *) &rth->local,
		    &addr_len) < 0) {
	perror("Cannot getsockname");
	return -1;
    }
    if (addr_len != sizeof(rth->local)) {
	fprintf(stderr, "Wrong address length %d\n", addr_len);
	return -1;
    }
    if (rth->local.nl_family != AF_NETLINK) {
	fprintf(stderr, "Wrong address family %d\n", rth->local.nl_family);
	return -1;
    }
    rth->seq = time(NULL);
    return 0;
}


int rtnl_open(struct rtnl_handle *rth, unsigned int subscriptions)
{
    return rtnl_open_byproto(rth, subscriptions, NETLINK_ROUTE);
}

void rtnl_close(struct rtnl_handle *rth)
{
    if (rth->fd >= 0) {
	close(rth->fd);
	rth->fd = -1;
    }
}

static int __rtnl_recvmsg(int fd, struct msghdr *msg, int flags)
{
    int len;

    do {
	len = recvmsg(fd, msg, flags);
    } while (len < 0 && (errno == EINTR || errno == EAGAIN));

    if (len < 0) {
	fprintf(stderr, "netlink receive error %s (%d)\n",
		strerror(errno), errno);
	return -errno;
    }

    if (len == 0) {
	fprintf(stderr, "EOF on netlink\n");
	return -ENODATA;
    }

    return len;
}

static int rtnl_recvmsg(int fd, struct msghdr *msg, char **answer)
{
    struct iovec *iov = msg->msg_iov;
    char *buf;
    int len;

    iov->iov_base = NULL;
    iov->iov_len = 0;

    len = __rtnl_recvmsg(fd, msg, MSG_PEEK | MSG_TRUNC);
    if (len < 0)
	return len;

    buf = malloc(len);
    if (!buf) {
	fprintf(stderr, "malloc error: not enough buffer\n");
	return -ENOMEM;
    }

    iov->iov_base = buf;
    iov->iov_len = len;

    len = __rtnl_recvmsg(fd, msg, 0);
    if (len < 0) {
	free(buf);
	return len;
    }

    if (answer)
	*answer = buf;
    else
	free(buf);

    return len;
}

static void rtnl_talk_error(struct nlmsghdr *h, struct nlmsgerr *err)
{
    fprintf(stderr, "RTNETLINK answers: %s\n", strerror(-err->error));
}

static int __rtnl_talk_iov(struct rtnl_handle *rtnl, struct iovec *iov,
			   size_t iovlen, struct nlmsghdr **answer,
			   bool show_rtnl_err)
{
    struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK };
    struct iovec riov;
    struct msghdr msg = {
	.msg_name = &nladdr,
	.msg_namelen = sizeof(nladdr),
	.msg_iov = iov,
	.msg_iovlen = iovlen,
    };
    unsigned int seq = 0;
    struct nlmsghdr *h;
    int i, status;
    char *buf;

    for (i = 0; i < iovlen; i++) {
	h = iov[i].iov_base;
	h->nlmsg_seq = seq = ++rtnl->seq;
	if (answer == NULL)
	    h->nlmsg_flags |= NLM_F_ACK;
    }

    status = sendmsg(rtnl->fd, &msg, 0);
    if (status < 0) {
	perror("Cannot talk to rtnetlink");
	return -1;
    }

    /* change msg to use the response iov */
    msg.msg_iov = &riov;
    msg.msg_iovlen = 1;
    i = 0;
    while (1) {
      next:
	status = rtnl_recvmsg(rtnl->fd, &msg, &buf);
	++i;

	if (status < 0)
	    return status;

	if (msg.msg_namelen != sizeof(nladdr)) {
	    fprintf(stderr,
		    "sender address length == %d\n", msg.msg_namelen);
	    exit(1);
	}
	for (h = (struct nlmsghdr *) buf; status >= sizeof(*h);) {
	    int len = h->nlmsg_len;
	    int l = len - sizeof(*h);

	    if (l < 0 || len > status) {
		if (msg.msg_flags & MSG_TRUNC) {
		    fprintf(stderr, "Truncated message\n");
		    free(buf);
		    return -1;
		}
		fprintf(stderr, "!!!malformed message: len=%d\n", len);
		exit(1);
	    }
	    if (nladdr.nl_pid != 0 ||
		h->nlmsg_pid != rtnl->local.nl_pid ||
		h->nlmsg_seq > seq || h->nlmsg_seq < seq - iovlen) {
		/* Don't forget to skip that message. */
		status -= NLMSG_ALIGN(len);
		h = (struct nlmsghdr *) ((char *) h + NLMSG_ALIGN(len));
		continue;
	    }

	    if (h->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA(h);

		if (l < sizeof(struct nlmsgerr)) {
		    fprintf(stderr, "ERROR truncated\n");
		} else if (!err->error) {

		    if (answer)
			*answer = (struct nlmsghdr *) buf;
		    else
			free(buf);
		    if (h->nlmsg_seq == seq)
			return 0;
		    else if (i < iovlen)
			goto next;
		    return 0;
		}

		if (rtnl->proto != NETLINK_SOCK_DIAG && show_rtnl_err)
		    rtnl_talk_error(h, err);

		errno = -err->error;
		free(buf);
		return -i;
	    }

	    if (answer) {
		*answer = (struct nlmsghdr *) buf;
		return 0;
	    }

	    fprintf(stderr, "Unexpected reply!!!\n");

	    status -= NLMSG_ALIGN(len);
	    h = (struct nlmsghdr *) ((char *) h + NLMSG_ALIGN(len));
	}
	free(buf);

	if (msg.msg_flags & MSG_TRUNC) {
	    fprintf(stderr, "Message truncated\n");
	    continue;
	}

	if (status) {
	    fprintf(stderr, "!!!Remnant of size %d\n", status);
	    exit(1);
	}
    }
}


static int __rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n,
		       struct nlmsghdr **answer, bool show_rtnl_err)
{
    struct iovec iov = {
	.iov_base = n,
	.iov_len = n->nlmsg_len
    };

    return __rtnl_talk_iov(rtnl, &iov, 1, answer, show_rtnl_err);
}

int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n,
	      struct nlmsghdr **answer)
{
    return __rtnl_talk(rtnl, n, answer, true);
}


#define parse_rtattr_nested(tb, max, rta) \
        (parse_rtattr((tb), (max), RTA_DATA(rta), RTA_PAYLOAD(rta)))

static inline const char *rta_getattr_str(const struct rtattr *rta)
{
    return (const char *) RTA_DATA(rta);
}

static inline __u32 rta_getattr_u32(const struct rtattr *rta)
{
    return *(__u32 *) RTA_DATA(rta);
}

static inline __u8 rta_getattr_u8(const struct rtattr *rta)
{
    return *(__u8 *) RTA_DATA(rta);
}

static inline __u16 rta_getattr_u16(const struct rtattr *rta)
{
    return *(__u16 *) RTA_DATA(rta);
}

int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
		       int len, unsigned short flags)
{
    unsigned short type;

    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
	type = rta->rta_type & ~flags;
	if ((type <= max) && (!tb[type]))
	    tb[type] = rta;
	rta = RTA_NEXT(rta, len);
    }
    if (len)
	fprintf(stderr, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
    return 0;
}

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    return parse_rtattr_flags(tb, max, rta, len, 0);
}

static const char *oper_states[] = {
    "unknown", "notpresent", "down", "lowerlayerdown",
    "testing", "dormant", "up"
};

static void print_operstate(__u8 state)
{
    if (state >= ARRAY_SIZE(oper_states))
	printf("state %#x\n", state);
    else
	printf("%s\n", oper_states[state]);
}

static void print_slave(struct rtattr *tb[])
{
    if (!tb)
	return;

    if (tb[IFLA_BOND_SLAVE_AD_AGGREGATOR_ID])
	printf("ad_aggregator_id: %d\n",
	       rta_getattr_u16(tb[IFLA_BOND_SLAVE_AD_AGGREGATOR_ID]));

    if (tb[IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE])
	printf("ad_actor_oper_port_state: %d\n",
	       rta_getattr_u8(tb
			      [IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE]));

    if (tb[IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE])
	printf("ad_partner_oper_port_state: %d\n",
	       rta_getattr_u16(tb
			       [IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE]));


}


static void print_linktype(struct rtattr *tb)
{
    struct rtattr *linkinfo[IFLA_INFO_MAX + 1];
    struct link_util *lu;
    struct link_util *slave_lu;
    char slave[32];

    parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, tb);

    if (linkinfo[IFLA_INFO_SLAVE_KIND]) {
	const char *kind = rta_getattr_str(linkinfo[IFLA_INFO_SLAVE_KIND]);

	if (!strncmp(kind, "bond", 4)) {

	    struct rtattr *attr[IFLA_BOND_SLAVE_MAX + 1], **data = NULL;

	    if (linkinfo[IFLA_INFO_SLAVE_DATA]) {
		parse_rtattr_nested(attr, IFLA_BOND_SLAVE_MAX,
				    linkinfo[IFLA_INFO_SLAVE_DATA]);
		data = attr;

		print_slave(data);
	    }
	}
    }
}


int print_linkinfo(const struct sockaddr_nl *who,
		   struct nlmsghdr *n, void *arg)
{
    FILE *fp = (FILE *) arg;
    struct ifinfomsg *ifi = NLMSG_DATA(n);
    struct rtattr *tb[IFLA_MAX + 1];
    int len = n->nlmsg_len;
    unsigned int m_flag = 0;
    const unsigned char *ifname;

    if (n->nlmsg_type != RTM_NEWLINK && n->nlmsg_type != RTM_DELLINK)
	return 0;

    len -= NLMSG_LENGTH(sizeof(*ifi));
    if (len < 0)
	return -1;

    parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);

    if (tb[IFLA_IFNAME])
	ifname = rta_getattr_str(tb[IFLA_IFNAME]);
    else
	fprintf(stderr, "BUG: device with ifindex %d has nil ifname\n",
		ifi->ifi_index);

    if (tb[IFLA_LINKINFO]) {
	if (tb[IFLA_OPERSTATE]) {
	    printf("%s: ", ifname);
	    print_operstate(rta_getattr_u8(tb[IFLA_OPERSTATE]));
	}
	print_linktype(tb[IFLA_LINKINFO]);
    }
}

int iplink_get(unsigned int flags, char *name, __u32 filt_mask)
{
    struct iplink_req req = {
	.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
	.n.nlmsg_flags = NLM_F_REQUEST,
	.n.nlmsg_type = RTM_GETLINK,
	.i.ifi_family = AF_PACKET,
    };
    struct nlmsghdr *answer;
    struct rtattr *linkinfo;
    char kind[IFNAMSIZ];
    int rc;

    if (name) {
	rc = addattr_l(&req.n, sizeof(req),
		       IFLA_IFNAME, name, strlen(name) + 1);
    }

    addattr32(&req.n, sizeof(req), IFLA_EXT_MASK, filt_mask);

    if (rtnl_talk(&rth, &req.n, &answer) < 0)
	return -2;

    print_linkinfo(NULL, answer, stdout);

    free(answer);
    return 0;
}
