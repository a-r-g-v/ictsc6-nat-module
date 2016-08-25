#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netfilter_bridge.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_arp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <net/checksum.h>
#define DRIVER_AUTHOR "a_r_g_v"
#define DRIVER_DESC "sugoi"
#define ADD_VLAN 50

// bit masks
#define VLAN_ID_FLAG 0x800
#define PRIVATE_A_NET 0x0a000000
#define PRIVATE_C_NET 0xc0a80000
#define NETWORK_A_MASK 0xff000000
#define NETWORK_B_MASK 0xffff0000
#define NETWORK_C_MASK 0xffffff00
#define UNDER_MASK 0x0000ffff
#define OUTSIDE_MASK 0xffff0000  // 10.0.0.0/16 ~ 10.15.0.0/16

static struct nf_hook_ops arp_in_nfho;
static struct nf_hook_ops arp_out_nfho;
static struct nf_hook_ops nfho;

struct arp_body {
	unsigned char src_mac[6];
	unsigned char src_ip[4];
	unsigned char dest_mac[6];
	unsigned char dest_ip[4];
};

struct arpbdy {
	__be16          ar_hrd;         /* format of hardware address   */
	__be16          ar_pro;         /* format of protocol address   */
	unsigned char   ar_hln;         /* length of hardware address   */
	unsigned char   ar_pln;         /* length of protocol address   */
	__be16          ar_op;          /* ARP opcode (command)         */

	unsigned char           ar_sha[ETH_ALEN];       /* sender hardware address      */
	unsigned char           saddr[4];              /* sender IP address            */
	unsigned char           ar_tha[ETH_ALEN];       /* target hardware address      */
	unsigned char           daddr[4];              /* target IP address            */
};

static unsigned int in_hook_func(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	struct ethhdr *ehdr = eth_hdr(skb);
	int team_id;
	unsigned int vlan_id;
	// IP
	if (ehdr->h_proto == 0x0008) {
		struct iphdr *iph = ip_hdr(skb);
		if (iph == NULL || iph->daddr == NULL || iph->saddr == NULL) {
			return NF_ACCEPT;
		}

		uint32_t daddr = ntohl(iph->daddr);
		uint32_t saddr = ntohl(iph->saddr);

		vlan_id = skb_vlan_tag_get_id(skb);
		team_id = vlan_id / 100;
		//printk(KERN_INFO "[Before IP IN] daddr %pI4, saddr %pI4  vlan_id: %d, team_id: %d \n", &iph->daddr, &iph->saddr, vlan_id, team_id);

		bool flag = false;
		//printk(KERN_INFO "daddr %x saddr %x \n",daddr, saddr );

		// DADDR: Incoming 192.168.0.0 ~ 192.168.255.255 , Rewrite 10.team_id.x.y
		if (daddr & NETWORK_B_MASK ==  PRIVATE_C_NET) {
			daddr = daddr & UNDER_MASK; // 0.0.x.y
			daddr |= PRIVATE_A_NET; // 10.0.x.y
			daddr |= team_id << 16; //10.team_id.x.y
			csum_replace2(&iph->check, iph->daddr, htonl(daddr)); // rewrite checksum

			// TCP Rewrite Checksum
			if(iph->protocol == 0x6) {
				struct tcphdr *tcph = tcp_hdr(skb);
        if(tcph == NULL || tcph->check == NULL) {
          return NF_ACCEPT;
        }
				csum_replace2(&tcph->check, iph->daddr, htonl(daddr));
				//printk(KERN_INFO "[After TCP DEST] tcp_check: %08x, old_check: %08x \n", tcph->check, old_check);
			}
			// UDP Rewrite Checksum
			else if (iph->protocol == 0x11) {
				struct udphdr *udph = udp_hdr(skb);
        if(udph == NULL || udph->check == NULL) {
          return NF_ACCEPT;
        }
				csum_replace2(&udph->check, iph->daddr, htonl(daddr));
				//printk(KERN_INFO "[After UDP DEST] udp_check: %08x, old_check: %08x \n", udph->check, old_check);
			}
			iph->daddr = htonl(daddr);
			flag = true;

		}

		// SADDR: Incoming 192.168.0.0 ~ 192.168.255.255 , Rewrite 10.team_id.x.y
		if (saddr & NETWORK_B_MASK ==  PRIVATE_C_NET) {
			saddr = saddr & UNDER_MASK; // 0.0.x.y
			saddr |= PRIVATE_A_NET; // 10.0.x.y
			saddr |= team_id << 16; //10.team_id.x.y
			csum_replace2(&iph->check, iph->saddr, htonl(saddr));
			// TCP, Calucate Checksum
			if(iph->protocol == 0x6) {
				struct tcphdr *tcph = tcp_hdr(skb);
        if(tcph == NULL || tcph->check == NULL) {
          return NF_ACCEPT;
        }
				csum_replace2(&tcph->check, iph->saddr, htonl(saddr));
				//printk(KERN_INFO "[After TCP SRC] tcp_check: %08x, old_check: %08x \n", tcph->check, old_check);
			// UDP, Calucate Checksum
			} else if (iph->protocol == 0x11) {
				struct udphdr *udph = udp_hdr(skb);
        if(udph == NULL || udph->check == NULL) {
          return NF_ACCEPT;
        }
				csum_replace2(&udph->check, iph->saddr, htonl(saddr));
				//printk(KERN_INFO "[After UDP SRC] udp_check: %08x, old_check: %08x \n", udph->check, old_check);
			}
			iph->saddr = htonl(saddr);
			flag = true;

		}
		if(flag){
			skb->vlan_tci += VLAN_ID_FLAG | ADD_VLAN;;  // 0x800 + 15
		}


		//printk(KERN_INFO "[After IP OUT] daddr %pI4, saddr %pI4  vlan_id: %d, team_id: %d \n", &iph->daddr, &iph->saddr, skb_vlan_tag_get_id(skb), team_id);
			return NF_ACCEPT;

	}
	// ARP
	else if (ehdr->h_proto == 0x0608) {
		struct arpbdy *arpb = (struct arpbdy *)arp_hdr(skb);
		if (!arpb){
			return NF_ACCEPT;
		}

		vlan_id = skb_vlan_tag_get_id(skb);
		team_id = vlan_id / 100;
		//printk(KERN_INFO "[Before ARP IN] daddr %pI4, saddr %pI4 vlan_id: %d, team_id: %d \n", arpb->daddr, arpb->saddr, vlan_id, team_id);

		if (!arpb->daddr || !arpb->saddr) {
			return NF_ACCEPT;
		}


		// if addr 192.168.0.0 ~ 192.168.255.255, rewrite 10.team_id.x.y
		if (arpb->daddr[0] == 192 && arpb->daddr[1] == 168 &&
				arpb->saddr[0] == 192 && arpb->saddr[1] == 168) {
			arpb->daddr[0] = arpb->saddr[0] = 10;
			arpb->daddr[1] = arpb->saddr[1] = team_id;
			skb->vlan_tci += VLAN_ID_FLAG | ADD_VLAN;
		}

		//printk(KERN_INFO "[After ARP IN] daddr %pI4, saddr %pI4 vlan_id: %d, team_id: %d \n", arpb->daddr, arpb->saddr, vlan_id, team_id);


	}
	return NF_ACCEPT;
}


static unsigned int out_hook_func(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	struct ethhdr *ehdr = eth_hdr(skb);
	unsigned int vlan_id;
	int team_id;

	// IP
	if (ehdr->h_proto == 0x0008) {
		struct iphdr *iph = ip_hdr(skb);
		if (iph == NULL || iph->daddr == NULL || iph->saddr == NULL) {
			return NF_ACCEPT;
		}

		vlan_id = skb_vlan_tag_get_id(skb); // 2000
		bool flag = false;
		uint32_t daddr = ntohl(iph->daddr);
		uint32_t saddr = ntohl(iph->saddr);

		//printk(KERN_INFO "[Before IP OUT] daddr %pI4, saddr %pI4  vlan_id: %d, team_id: %d \n", &iph->daddr, &iph->saddr, skb_vlan_tag_get_id(skb), team_id);
		if (daddr & NETWORK_A_MASK == PRIVATE_A_NET && !(vlan_id & VLAN_ID_FLAG)) {
			daddr = daddr & UNDER_MASK; // 0.0.x.y
			daddr |= PRIVATE_C_NET; // 192.168.x.y
			csum_replace2(&iph->check, iph->daddr, htonl(daddr));
			if(iph->protocol == 0x6) {
				struct tcphdr *tcph = tcp_hdr(skb);
				csum_replace2(&tcph->check, iph->daddr, htonl(daddr));
				//printk(KERN_INFO "[After TCP DEST] tcp_check: %08x, old_check: %08x \n", tcph->check, old_check);
			} else if (iph->protocol == 0x11) {
				struct udphdr *udph = udp_hdr(skb);
				csum_replace2(&udph->check, iph->daddr, htonl(daddr));
				//printk(KERN_INFO "[After UDP DEST] udp_check: %08x, old_check: %08x \n", udph->check, old_check);
			}
			iph->daddr = htonl(daddr);
			flag = true;
		}
		if (saddr & NETWORK_A_MASK == PRIVATE_A_NET && !(vlan_id & VLAN_ID_FLAG)) {
			saddr = saddr & UNDER_MASK; // 0.0.x.y
			saddr |= PRIVATE_C_NET; // 192.168.x.y
			csum_replace2(&iph->check, iph->saddr, htonl(saddr));
			if(iph->protocol == 0x6) {
				struct tcphdr *tcph = tcp_hdr(skb);
        if (tcph == NULL || tcph->check == NULL ) {
          return NF_ACCEPT; 
        }
				csum_replace2(&tcph->check, iph->saddr, htonl(saddr));
				//printk(KERN_INFO "[After TCP DEST] tcp_check: %08x, old_check: %08x \n", tcph->check, old_check);
			} else if (iph->protocol == 0x11) {
				struct udphdr *udph = udp_hdr(skb);
        if (udph == NULL || udph->check == NULL ) {
          return NF_ACCEPT; 
        }
				csum_replace2(&udph->check, iph->saddr, htonl(saddr));
				//printk(KERN_INFO "[After UDP DEST] udp_check: %08x, old_check: %08x \n", udph->check, old_check);
			}
			iph->saddr = htonl(saddr);
			flag = true;
		}

		if(flag) {
			skb->vlan_tci -= ADD_VLAN;	
		}
		skb->vlan_tci &= ~(VLAN_ID_FLAG);
		//printk(KERN_INFO "[After IP OUT] daddr %pI4, saddr %pI4  vlan_id: %d, team_id: %d \n", &iph->daddr, &iph->saddr, skb_vlan_tag_get_id(skb), team_id);
	}
	// ARP
	else if (ehdr->h_proto == 0x0608) {
		struct arpbdy *arpb = (struct arpbdy *)arp_hdr(skb);
		if (!arpb){
			return NF_ACCEPT;
		}

		vlan_id = skb_vlan_tag_get_id(skb); // 2000
		team_id = vlan_id / 100;
		//printk(KERN_INFO "[Before ARP OUT] daddr %pI4, saddr %pI4 vlan_id: %d, team_id: %d \n", arpb->daddr, arpb->saddr, vlan_id, team_id);

		if (!arpb->daddr || !arpb->saddr) {
			return NF_ACCEPT;
		}

		if (skb->vlan_tci & VLAN_ID_FLAG){
			skb->vlan_tci &= ~(VLAN_ID_FLAG);
		}
		// if addr 10.1.0.0 ~ 10.15.255.255, rewrite 192.168.x.y
		else if (arpb->daddr[0] == 10 && arpb->daddr[1] >= 0 && arpb->daddr[1] <= 15  &&
				arpb->saddr[0] == 10 && arpb->saddr[1] >= 0 && arpb->saddr[1] <= 15) {
			arpb->daddr[0] = arpb->saddr[0] = 192;
			arpb->daddr[1] = arpb->saddr[1] = 168;
			skb->vlan_tci -= ADD_VLAN;
		}
		//printk(KERN_INFO "[After ARP OUT] daddr %pI4, saddr %pI4 vlan_id: %d, team_id: %d !!!vlan_id!!!: %d \n", arpb->daddr, arpb->saddr, vlan_id, team_id, skb_vlan_tag_get_id(skb));
	}

	return NF_ACCEPT;
}

//----------------------------------
static int __init nfe_init(void)
{

	arp_in_nfho.hook = in_hook_func;
	arp_in_nfho.hooknum =NF_BR_PRE_ROUTING;
	arp_in_nfho.pf = PF_BRIDGE;
	nf_register_hook(&arp_in_nfho);


	arp_out_nfho.hook = out_hook_func;
	arp_out_nfho.hooknum =NF_BR_FORWARD;
	arp_out_nfho.pf = PF_BRIDGE;
	nf_register_hook(&arp_out_nfho);


	return 0;
}
//----------------------------------
static void __exit nfe_exit(void)
{
	nf_unregister_hook(&arp_in_nfho);
	nf_unregister_hook(&arp_out_nfho);
}
module_init(nfe_init);
module_exit(nfe_exit);
MODULE_LICENSE("GPLv3");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);

