#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <netlink/netlink.h>
#include <libmnl/libmnl.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include <linux/genetlink.h>


#define SSID_MAX_LENGTH_WITH_NULL 32
#define MAC_ADDRESS_LENGTH 17
#define WIFI_LIST_MAX_LENGTH 300
#define INTF_NAME_MAX_LENGTH 30
#define SECURITY_MODE_MAX_LENGTH 5


typedef struct nl_sock nl_sock;
typedef struct nl_cb nl_cb;
typedef struct nlattr nlattr;
typedef struct nl_msg nl_msg;
typedef struct genlmsghdr genlmsghdr;


typedef struct
{
	nl_sock *socket;
	nl_cb *call_back;
	int msg_sent;
	int driver_id;
	unsigned int if_index;
	char if_name[INTF_NAME_MAX_LENGTH];
} nl80211_socket;


typedef struct
{
	char security_mode[SECURITY_MODE_MAX_LENGTH];
	char ssid[SSID_MAX_LENGTH_WITH_NULL];
	char mac[MAC_ADDRESS_LENGTH];
	unsigned int channel;
	int signal;
} wiphy_info;


typedef struct
{
	int size;
	wiphy_info container[WIFI_LIST_MAX_LENGTH];
} wiphy_list;


int is_number(char *str)
{
	int i = 0;
	while (str[i] != '\0')
	{
		if(!isdigit(str[i]))
			return 0;
		i++;
	}

	return 1;
}


void parse_security_mode(unsigned char *ie, int ielen, char *security_mode)
{
	int found_id = 0;

	while (ielen >= 2 && ielen >= ie[1])
	{
		if (ie[0] == 48 || ie[0] == 221)
			break;

		ielen -= ie[1] + 2;
		ie += ie[1] + 2;
	}

	found_id = ie[0];

	if (found_id = 48)
	{
		if (ie[7] == 1 || ie[7] == 5)
			strcpy(security_mode, "WEP");
		else if (ie[7] == 2 || ie[7] == 4)
			strcpy(security_mode, "WPA2");
		else
			strcpy(security_mode, "Free");
	}
	else if (found_id == 221)
	{
		if (ie[7] == 1 || ie[7] == 5)
			strcpy(security_mode, "WEP");
		else if (ie[7] == 2 || ie[7] == 4)
			strcpy(security_mode, "WPA");
		else
			strcpy(security_mode, "Free");
	}
	else
		strcpy(security_mode, "Free");
}


void parse_mac(char *mac_addr, unsigned char *arg)
{
	int i, l = 0;

	for (i = 0; i < 6; i++)
	{
		if (i == 0)
		{
			sprintf(mac_addr+l, "%02x", arg[i]);
			l += 2;
		}
		else
		{
			sprintf(mac_addr+l, ":%02x", arg[i]);
			l += 3;
		}
	}
}


void parse_ssid(nlattr *attr, char ssid[SSID_MAX_LENGTH_WITH_NULL])
{
	const char *payload = mnl_attr_get_payload(attr);
	int len = mnl_attr_get_payload_len(attr);

	if (len == 0 || payload[0] != 0 || payload[1] >= SSID_MAX_LENGTH_WITH_NULL || payload[1] > len - 2)
		return;

	int ssid_len = payload[1];
	strncpy(ssid, payload + 2, ssid_len);
	ssid[ssid_len] = '\0';
}



int frequency_to_channel(int freq)
{
	if (freq == 2484)
		return 14;

	if (freq < 2484)
		return (freq - 2407) / 5;

	if (freq < 45000)
		return freq/5 - 1000;

	if (freq >= 58320 && freq <= 64800)
		return (freq - 56160) / 2160;

	return 0;
}


static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}


static int get_wiphy_list_cb(struct nl_msg *msg, void *arg)
{
	wiphy_list *list = (wiphy_list *)arg;
	genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	nlattr *tb[NL80211_ATTR_MAX + 1];
	nlattr *bss[NL80211_BSS_MAX + 1];

	struct nla_policy bss_policy[NL80211_BSS_MAX + 1] =
	{
		[NL80211_BSS_TSF] = { .type = NLA_U64 },
		[NL80211_BSS_FREQUENCY] = { .type = NLA_U32 },
		[NL80211_BSS_BSSID] = { },
		[NL80211_BSS_BEACON_INTERVAL] = { .type = NLA_U16 },
		[NL80211_BSS_CAPABILITY] = { .type = NLA_U16 },
		[NL80211_BSS_INFORMATION_ELEMENTS] = { },
		[NL80211_BSS_SIGNAL_MBM] = { .type = NLA_U32 },
		[NL80211_BSS_SIGNAL_UNSPEC] = { .type = NLA_U8 },
		[NL80211_BSS_STATUS] = { .type = NLA_U32 },
		[NL80211_BSS_SEEN_MS_AGO] = { .type = NLA_U32 },
		[NL80211_BSS_BEACON_IES] = { },
	};

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
	if (!tb[NL80211_ATTR_BSS])
		return NL_SKIP;

	if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy))
		return NL_SKIP;

	if (		!bss[NL80211_BSS_BSSID] ||
			!bss[NL80211_BSS_INFORMATION_ELEMENTS] ||
			!bss[NL80211_BSS_FREQUENCY] ||
			!bss[NL80211_BSS_SIGNAL_MBM])
		return NL_SKIP;

	parse_mac(list->container[list->size].mac, nla_data(bss[NL80211_BSS_BSSID]));
	parse_ssid(bss[NL80211_BSS_INFORMATION_ELEMENTS], list->container[list->size].ssid);
	parse_security_mode(nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]), nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]), list->container[list->size].security_mode);
	list->container[list->size].channel = frequency_to_channel(nla_get_u32(bss[NL80211_BSS_FREQUENCY]));
	list->container[list->size].signal = ((int)nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]))/100;
	list->size++;

	return NL_SKIP;
}


int process_input(nl80211_socket *sk, int *frequency, int num, char **argv)
{
	if (num == 2)
	{
		strcpy(sk->if_name, argv[1]);
		return 0;
	}
	else if (num == 4 && strcmp(argv[2], "-s") == 0 && is_number(argv[3]))
	{
		strcpy(sk->if_name, argv[1]);
		*frequency = atoi(argv[3]);
		return 0;
	}

	return 1;
}


int init_nl80211_socket(nl80211_socket *sk, wiphy_list *list)
{
	sk->socket = nl_socket_alloc();
	if (!sk->socket)
	{
		printf("Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	if (genl_connect(sk->socket))
	{
		printf("Failed to connect to netlink socket.\n");
		nl_close(sk->socket);
		nl_socket_free(sk->socket);
		return -ENOLINK;
	}

	sk->driver_id = genl_ctrl_resolve(sk->socket, NL80211_GENL_NAME);
	if (sk->driver_id< 0)
	{
		printf("Nl80211 interface not found.\n");
		nl_close(sk->socket);
		nl_socket_free(sk->socket);
		return -ENOENT;
	}

	sk->call_back = nl_cb_alloc(NL_CB_DEFAULT);
	if (!sk->call_back)
	{
		printf("Failed to allocate netlink callback.\n"); 
		nl_close(sk->socket);
		nl_socket_free(sk->socket);
		return ENOMEM;
	}

	sk->if_index = if_nametoindex(sk->if_name);
	if (sk->if_index == 0)
	{
		printf("Wrong name of interface");
		nl_close(sk->socket);
		nl_socket_free(sk->socket);
		return ENOENT;
	}

	nl_cb_set(sk->call_back, NL_CB_VALID , NL_CB_CUSTOM, get_wiphy_list_cb, list);
	nl_cb_set(sk->call_back, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &(sk->msg_sent));

	return sk->driver_id;
}


int trigger_scan(nl80211_socket *sk)
{
	nl_msg *msg;
	nl_msg *ssids_to_scan;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	ssids_to_scan = nlmsg_alloc();
	if (!ssids_to_scan)
	{
		nlmsg_free(msg);
		return -ENOMEM;
	}

	genlmsg_put(msg, 0, 0, sk->driver_id, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, sk->if_index);
	nla_put(ssids_to_scan, 1, 0, "");
	nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids_to_scan);

	nlmsg_free(ssids_to_scan);

	int ret = nl_send_auto(sk->socket, msg);
	if (ret <= 0)
	{
		nlmsg_free(msg);
		return -2;
	}

	nlmsg_free(msg);

	return 0;
}


int get_wiphy_list(nl80211_socket *sk, wiphy_list *list)
{
	nl_msg* msg = nlmsg_alloc();
	if (!msg)
	{
		return -2;
	}

	list->size = 0;

	sk->msg_sent = 1;
	genlmsg_put(	msg,
			0,
			0,
			sk->driver_id,
			0,
			NLM_F_DUMP,
			NL80211_CMD_GET_SCAN,
			0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, sk->if_index);

	int ret = nl_send_auto(sk->socket, msg);
	if (ret <= 0)
	{
		nlmsg_free(msg);
		return -2;
	}

	while (sk->msg_sent > 0)
		nl_recvmsgs(sk->socket, sk->call_back);

	nlmsg_free(msg);

	return 0;
}

void dump_wiphy_info(wiphy_list *list)
{
	printf("+-----------------------------------------------------------------------------------------+\n");
	printf("|                                      WIFI SCANNER                                       |\n");
	printf("+---+----------------------------+-------------------+---------+----------+---------------+\n");
	printf("| № |            NAME            |        MAC        | CHANNEL |  SIGNAL  | SECURITY MODE |\n");
	printf("+---+----------------------------+-------------------+---------+----------+---------------+\n");
	
	for (int i = 0; i < list->size; i++)
	{
		printf("|%3i|", i+1);
		printf("%28s|", list->container[i].ssid);
		printf(" %s |", list->container[i].mac);
		printf("%9i|", list->container[i].channel);
		printf("%10i|", list->container[i].signal);
		printf("%15s|\n", list->container[i].security_mode);
		printf("+---+----------------------------+-------------------+---------+----------+---------------+\n");
	}
}


int main(int argc, char **argv)
{
	nl80211_socket sk;
	wiphy_list list;
	int frequency = 0;

	if (process_input(&sk, &frequency, argc, argv))
	{
		printf("Wrong input!\n");
		return 1;
	}

	if (init_nl80211_socket(&sk, &list) < 0)
	{
		printf("Error initializing netlink 802.11\n");
		return -1;
	}

	while (1)
	{
		system("clear");

		trigger_scan(&sk);

		if (get_wiphy_list(&sk, &list))
			continue;

		dump_wiphy_info(&list);
		sleep(frequency);
	}

	return 0;
}
