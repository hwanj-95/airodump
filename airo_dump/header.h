#ifndef HEADER_H
#define HEADER_H

#endif // HEADER_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h> //ipv4 ip_addr
#include <arpa/inet.h> // inet_ntoa > net add change
//#include <netinet/tcp.h>
#include <net/ethernet.h> //Use ETHERTYPE_IP
#include <linux/in.h> //Use IPPROTO_TCP#
#include <algorithm>
#include <string.h>
#include <cstring>
using namespace std;

#define MAC_LEN 6
#define TIMESTAMP 8
#define beacon_fraame 0x0080
#define probe_req 0x0040
#define probe_res 0x0005
#define skip_channel 12

#pragma pack(push, 1)
struct radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present1;     /* fields present */
        u_int32_t       it_present2;
        u_int8_t        flags;
        u_int8_t        rate;
        u_int16_t       chan_freq;
        u_int16_t       chan_flags;
        u_int8_t        antsignal_1;
        u_int8_t        padding;
        u_int16_t       rx_flags;
        u_int8_t        antsignal_2;
        u_int8_t        ant;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct beacon_header{
    u_int16_t Type;
    u_int16_t Type_padding;
    u_int8_t Des_addr[MAC_LEN];
    u_int8_t Sour_addr[MAC_LEN];
    u_int8_t Bss_id[MAC_LEN];
    u_int16_t number;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct wireless_header{
    u_int8_t Timestamp[TIMESTAMP];
    u_int16_t Beacon_interval;
    u_int16_t Capabilties_info;
    u_int8_t Tag_num;
    u_int8_t ssid_len;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct probe_header{
    u_int8_t Tag_num;
    u_int8_t ssid_len;
};
#pragma pack(pop)
