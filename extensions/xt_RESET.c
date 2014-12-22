/*  ------------------------------------------------------------------------
	xt_RESET - A xtables target for resetting TCP connections.
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

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/icmp.h>
#include <net/tcp.h>
#include <linux/netfilter/x_tables.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lance Alt <lancealt@gamil.org>");
MODULE_DESCRIPTION("Xtables: packet \"reset\" target for IPv4");

static unsigned int
reset_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct tcphdr* tcp;
	struct iphdr* ip;
	int len;
	uint32_t temp;

	tcp = tcp_hdr(skb);
	ip = ip_hdr(skb);

	if(!tcp || !ip) {
		return NF_ACCEPT;
	}

	skb_make_writable(skb, skb->len);

	tcp->syn = false;
	tcp->ack = true;
	tcp->rst = true;
	tcp->seq = 0;
	tcp->window = 0;

	len = skb->len;
	tcp->check = 0;
	tcp->check = tcp_v4_check(len - 4*ip->ihl,
			ip->saddr, ip->daddr,
			csum_partial((char*)tcp, len - 4*ip->ihl,0));

	ip->check = 0;
	ip->check = ip_fast_csum((u8*)ip, ip->ihl);

	printk(KERN_INFO "xt_reset: Sending RST\n");

	return XT_CONTINUE;
}

static struct xt_target reset_tg_reg __read_mostly = {
	.name		= "RESET",
	.family		= NFPROTO_IPV4,
	.target		= reset_tg,
	.table		= "filter",
	.me		= THIS_MODULE,
};

static int __init reset_tg_init(void)
{
	printk(KERN_INFO "xt_RESET: init\n");
	return xt_register_target(&reset_tg_reg);
}

static void __exit reset_tg_exit(void)
{
	printk(KERN_INFO "xt_RESET: exit\n");
	xt_unregister_target(&reset_tg_reg);
}

module_init(reset_tg_init);
module_exit(reset_tg_exit);
