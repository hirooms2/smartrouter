#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <vector>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

using namespace std;

struct ip *iph;
struct tcphdr *tcph;

bool isSame(vector<int> ip1, vector<int> ip2){
    bool ok = true;
    for(int i=0;i<4;i++)
        if(ip1[i]!=ip2[i])
            ok=false;
    return ok;
}
vector<vector<int> > v;
void pcapHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    int length = header->len;

    struct ieee80211_hdr {
        uint16_t frame_control;
        uint16_t duration_id;
        uint8_t addr1[6];
        uint8_t addr2[6];
        uint8_t addr3[6];
        uint16_t seq_ctrl;
        uint8_t addr4[6];

    };
    struct radiotap_header{
        uint8_t it_rev;
        uint8_t it_pad;
        uint16_t it_len;
    };
    const u_char *bssid;
    const u_char *essid;
    const u_char *essidLen;
    const u_char *channel;
    const u_char *rssi;

    int offset = 0;
    struct radiotap_header *radio_hdr;
    radio_hdr = (struct radiotap_header *)packet;
    offset = radio_hdr->it_len;
    struct ieee80211_hdr *mgnt_hdr;
    mgnt_hdr = (struct ieee80211_hdr *)(packet+offset);

    bssid = packet + 42;
    essid = packet + 50;
    essidLen = packet + 63;
    rssi = packet + 22;
    signed int rssiDbm = rssi[0] - 256;
    channel = packet + 18;
    int channelFreq = channel[1] * 256 + channel[0];

    char *ssid = (char*)malloc(63);
    unsigned int i = 0;
    while(essid[i] > 0x1) {
        ssid[i] = essid[i];
        i++;
    }
    /* 
    //beacon

    ssid[i] = '\0';
    printf("RSSI: %d dBm\n", rssiDbm);
    printf("Ap Frequency: %iMhz", channelFreq);
    printf("ESSID length: %i bytes.\n",essidLen);
    printf("BSSID string: %02X:%02X:%02X:%02X:%02X:%02X\n", bssid[0], bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
    printf("offset %d\n",offset);
    */

    
    //probe

    vector<int > t;
    for(int i=offset+10;i<offset+16;i++){
        t.push_back(packet[i]);
    }
    bool isNew = true;
    for(int i=0;i<v.size();i++){
        if(isSame(t, v[i]))
            isNew=false;
    }
    if(isNew && rssiDbm > -70){
        int c = v.size();
        v.push_back(t);
        printf("%d.Sender Ether %02X:%02X:%02X:%02X:%02X:%02X",v.size(),v[c][0],v[c][1],v[c][2],v[c][3],v[c][4],v[c][5]);
        printf(" RSSI: %d dBm ESSID string: %s\n", rssiDbm,ssid);
    }
    
    /*   int j=1;
    for(int i=offset;i<length;i++){
        if((i-offset)==16*j){
            printf("\n");
            j++;
        }
        printf("%02X:",packet[i]);
    
    }
    printf("\nframe: %u\n", packet[offset]);
*/
}
int main(int argc, char **argv)
{
    char *dev;
    char *net;
    char *mask;
    
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    struct pcap_pkthdr hdr;
    struct in_addr net_addr, mask_addr;
    struct ether_header *eptr;
    const u_char *packet;

    struct bpf_program fp;

    pcap_t *pcd;

    dev = pcap_lookupdev(errbuf);

    if(dev==NULL){
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("DEV: %s\n", dev);

    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

    if(ret==-1){
        printf("%s\n", errbuf);
        exit(1);
    }
    net_addr.s_addr = netp;
    net = inet_ntoa(net_addr);

    if(net==NULL){
        perror("inet_ntoa");
        exit(1);
    }
    printf("NET: %S\n",net);

    mask_addr.s_addr = maskp;
    mask = inet_ntoa(mask_addr);
    printf("MSK: %s\n", mask);
    printf("===========\n");

    pcd = pcap_open_live(argv[1], BUFSIZ, 0, 0, errbuf);
    if(pcd == NULL){
        printf("%s\n", errbuf);
        exit(1);
    }
    if(pcap_compile(pcd, &fp, "type mgt subtype probe-req", 0, netp) == -1){
        printf("compile error\n");
        exit(1);
    }
    if(pcap_setfilter(pcd, &fp) == -1){
        printf("setfilter error\n");
        exit(1);
    }
    pcap_loop(pcd, 0, pcapHandler, NULL);
    //pcap_dispatch(pcd,0, pcapHandler, NULL);
    return 0;
}


