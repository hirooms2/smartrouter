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
    for(int i=0;i<4;i++){
        if(ip1[i]!=ip2[i]){
            ok=false;
        }
    }
    return ok;
}
vector<vector<int> > v;

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    static int count = 1;
    struct ether_header *ep;
    unsigned short ether_type;
    int chcnt = 0;
    int length = pkthdr->len;
    int len=length;
    int i;
    ep = (struct ether_header *)packet;

    packet+=sizeof(struct ether_header);

    ether_type = ntohs(ep->ether_type);
    if(ether_type == ETHERTYPE_IP){
        iph = (struct ip*)packet;
        printf("IP Packet\n");
        printf("Version: %d\n", iph->ip_v);
        printf("Header Len: %d\n", iph->ip_hl);
        printf("Ident: %d\n", ntohs(iph->ip_id));
        printf("TTL: %d\n", iph->ip_ttl);
        printf("Src Address: %s\n", inet_ntoa(iph->ip_src));
        printf("Dst Address: %s\n", inet_ntoa(iph->ip_dst));

        if(iph->ip_p == IPPROTO_TCP){
            tcph = (struct tcphdr*)(packet+iph->ip_hl*4);
            printf("Src Port: %d\n", ntohs(tcph->source));
            printf("Dst Port: %d\n", ntohs(tcph->dest));
        }
        while(length--){
            printf("%02X ", *(packet++));
            if((++chcnt % 16) == 0)
                printf("\n");
        }
    }
    else if(ether_type == ETHERTYPE_ARP){
        //printf("Ethernet type hex:%x dev:%d is an ARP packet\n",
        //        ntohs(ep->ether_type),ntohs(ep->ether_type));
        /*for(i=0;i<length;i++){
            printf("%02x ", packet[i]);
            if((++chcnt % 16) == 0)
                printf("\n");
        }*/
        
        vector<int> t;
        //printf("\nSender: ");
        for(i=0;i<4;i++){
        //    printf("%d.", packet[14+i]);
            t.push_back(packet[14+i]);
        }
        //printf("\n");

        bool isNew = true;
        for(i=0;i<v.size();i++){
            if(isSame(t, v[i]))
                isNew=false;
        }

        if(isNew){
            int c = v.size();
            v.push_back(t);
            printf("%d.Sender IP %d.%d.%d.%d\n",v.size(),v[c][0],v[c][1], v[c][2],v[c][3] );            
        }

       /* printf("\nTarget: ");
         for(i=0;i<4;i++){
            printf("%d.", packet[24+i]);
        }
        printf("\n");
        */

    }
    else {
        printf("NONE IP PACKET\n");
    }
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

    //pcd = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
    pcd = pcap_create(dev, errbuf);
    if(pcd==NULL){
        printf("create error\n");
        exit(1);
    }

    if(pcap_set_rfmon(pcd, 0)==0){
        printf("monitor mode enabled\n");
    }
    pcap_set_snaplen(pcd, BUFSIZ);
    pcap_set_promisc(pcd, 1);
    pcap_set_timeout(pcd, 0);
    if(pcap_activate(pcd)==0){
        printf("pcap activate\n");
    } else {
        printf("activation fail\n");
        exit(1);
    }

    if(pcd == NULL){
        printf("%s\n", errbuf);
        exit(1);
    }
    if(pcap_compile(pcd, &fp, "arp", 0, 0) == -1){
        printf("compile error\n");
        exit(1);
    }
    if(pcap_setfilter(pcd, &fp) == -1){
        printf("setfilter error\n");
        exit(1);
    }
    pcap_loop(pcd, 0, callback, NULL);
}


