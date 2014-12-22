/*  ------------------------------------------------------------------------
	xt_notarpit - A xtables match for detecting network tarpits.
	Copyright (c) 2014, Lance Alt

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published
	by the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with this program. If not, see <http://www.gnu.org/licenses/>.
	------------------------------------------------------------------------ */

#include <linux/if.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/netfilter/x_tables.h>
#include "compat_xtables.h"
#include <linux/tcp.h>
#include <linux/ip.h>
#include <net/ip.h>

MODULE_AUTHOR("Lance Alt <lancealt@gmail.com>");
MODULE_DESCRIPTION("Xtables: notarpit match module");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_notarpit");
MODULE_ALIAS("ip6t_notarpit");


bool xt_notarpit_mt(const struct sk_buff *skb,
    struct xt_action_param *par)
{
	struct tcphdr* tcp = tcp_hdr(skb);
	struct iphdr* ip = ip_hdr(skb);
	int flags;
	uint16_t window;

	if(!tcp || !ip) {
		return false;
	}

	/* Only match SYN/ACKs */
	if(!(tcp->syn && tcp->ack)) {
		return false;
	}

	/* If there are TCP Options, match fails */
	if(tcp_optlen(skb) > 0) {
		return false;
	}

	window = ntohs(tcp->window);

	/* If the window size is greater than the threshold or not zero, match fails */
	if(window > 20 || window == 0) {
		return false;
	}


	flags = tcp->fin + (tcp->syn << 1) + (tcp->rst << 2) + (tcp->psh << 3) + (tcp->ack << 4);
	printk(KERN_INFO "Tarpit Detected: ipaddr=%u.%u.%u.%u, port=%u, flags=0x%x, window=%u, options=%u\n",
			(ip->saddr >> 0) & 0xff, (ip->saddr >> 8) & 0xff,
			(ip->saddr >> 16) & 0xff, (ip->saddr >> 24) & 0xff,
			htons(tcp->source), flags, window, tcp_optlen(skb));


	return true;
}

static struct xt_match xt_notarpit_mt_reg[] __read_mostly = {
	{
		.name       = "notarpit",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.match      = xt_notarpit_mt,
		.me         = THIS_MODULE,
	},
	{
		.name       = "notarpit",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.match      = xt_notarpit_mt,
		.me         = THIS_MODULE,
	},
};

static int __init xt_notarpit_match_init(void)
{
	printk(KERN_INFO "notarpit: init!\n");
	return xt_register_matches(xt_notarpit_mt_reg,
		ARRAY_SIZE(xt_notarpit_mt_reg));
}

static void __exit xt_notarpit_match_exit(void)
{
	printk(KERN_INFO "notarpit: exit!\n");
	xt_unregister_matches(xt_notarpit_mt_reg, ARRAY_SIZE(xt_notarpit_mt_reg));
}

module_init(xt_notarpit_match_init);
module_exit(xt_notarpit_match_exit);
