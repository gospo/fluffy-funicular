/*
 * Fluffy Funicular Listener (random naming thanks to github)
 * Copyright 2018, Andy Gospodarek
 * SPDX-License-Identifier: GPL-2.0
 */

#include "ff.h"

#define MAX_NETDEVS	16
char netdevs[MAX_NETDEVS][IFNAMSIZ];
struct rtnl_handle rth = {.fd = -1 };

void ff_netlink_dump(char *netdev)
{
    if (rtnl_open(&rth, 0) < 0) {
	fprintf(stderr, "Cannot open rtnetlink\n");
	exit(-1);
    }

    iplink_get(NLM_F_DUMP, netdev, RTEXT_FILTER_VF);
    rtnl_close(&rth);
}


void ff_print_help(void)
{
    printf("Usage: ff DEVICE\n"
	   "\n" "where DEVICE := netdevs to check\n");
    exit(0);
}

int main(int argc, char *argv[])
{
    int i;

    if (argc == 1)
	/* print_help(); */
	ff_print_help();
    else if (argc == 2 &&
	     (!strncmp(argv[1], "-h", sizeof(argv[1])) ||
	      !strncmp(argv[1], "-help", sizeof(argv[1])) ||
	      !strncmp(argv[1], "--help", sizeof(argv[1]))))
	ff_print_help();

    ff_netlink_dump(argv[1]);
}
