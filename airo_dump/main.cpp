 #include "header.h"

using namespace std;

struct output{
    u_int8_t BSSID[MAC_LEN];
    u_int8_t PWR;
    int BEACONS;
    u_int8_t SSID[MAC_LEN];
};

void usage(){
    printf("syntax: test <interface>\n");
    printf("sample: test mon0\n");
}
u_int8_t cha(u_int8_t pa){
    u_int8_t change;
    change = ~pa;
    change = change + 1;
    //printf("%d \n",change);
    return change;
}

int main(int argc, char* argv[]){

    if (argc != 2) {
        usage();
        return -1;
    }
    struct output out;

    struct radiotap_header* rah;
    struct beacon_header* bea;
    struct wireless_header* wir;

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    printf("--------------------------------------------------------------------------------\n");
    printf("BSSID\t\t\tPWR\t\tBeacons\t\t\tESSID\n");
    printf("--------------------------------------------------------------------------------\n");


    while(true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }



        rah = (struct radiotap_header*)packet;
        bea = (struct beacon_header*)(packet+rah->it_len);
        wir = (struct wireless_header*)(packet+rah->it_len+sizeof(struct beacon_header));
        packet = packet + rah->it_len+sizeof(struct beacon_header)+sizeof(struct wireless_header);
        //printf("test\n");
        //printf("radio len : %d\n", rah->it_len);
        //cha(rah->antsignal_1);
//        printf("PWR : -%d\n",cha(rah->antsignal_1));
//        printf("beacon : 0x%04x\n",bea->Type);
//        printf("BSSID : %02x:%02x:%02x:%02x:%02x:%02x\n",
//               bea->Bss_id[0],bea->Bss_id[1],
//               bea->Bss_id[2],bea->Bss_id[3],
//               bea->Bss_id[4],bea->Bss_id[5]);
//        printf("SSID len : %d\n",wir->ssid_len);
//        for(int i = 0; i<wir->ssid_len; i++){
//            printf("%c", packet[i]);
//        }
//        printf("\n");
//        printf("channel : %d\n",packet[wir->ssid_len+skip_channel]);
//        printf("\n");
//        if(bea->Type == beacon_fraame){
//            printf("%02x:%02x:%02x:%02x:%02x:%02x\t",
//                           bea->Bss_id[0],bea->Bss_id[1],
//                           bea->Bss_id[2],bea->Bss_id[3],
//                           bea->Bss_id[4],bea->Bss_id[5]);
//            printf("-%d\t\t",cha(rah->antsignal_1));
//            printf("0x%04x\t\t\t",bea->Type);
//            for(int i = 0; i<wir->ssid_len; i++){
//                        printf("%c", packet[i]);
//                    }
//            printf("\t");
//            printf("\n");

//        }
        //printf("channel : %d\n",packet[wir->ssid_len+skip_channel]);

//        memcpy(out[0].BSSID, bea->Bss_id, MAC_LEN);

//        for(int j=0; j<MAC_LEN; j++){
//            printf("%02x:",out[0].BSSID[j]);
//        }
//        printf("\n");
//        int cmp = memcmp(&out[0].BSSID, &bea->Bss_id, sizeof(bea->Bss_id));
//        if(cmp == 0){
//            printf("good\n");
//        }else printf("sibal\n");
//        for(int i=0; i<1; i++){
//            if(bea->Type == beacon_fraame){
//                memcpy(out.BSSID, bea->Bss_id, sizeof(bea->Bss_id));
//                printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
//                       out.BSSID[0],out.BSSID[1],
//                       out.BSSID[2],out.BSSID[3],
//                       out.BSSID[4],out.BSSID[5]);
//                printf("----------------------------------------\n");
//            }
//        }
//        printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
//                                   bea->Bss_id[0],bea->Bss_id[1],
//                                   bea->Bss_id[2],bea->Bss_id[3],
//                                   bea->Bss_id[4],bea->Bss_id[5]);







    }
    printf("\n\n");

    pcap_close(handle);
}
