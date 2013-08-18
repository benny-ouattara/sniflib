#ifndef __SNIFFER_h__
#define __SNIFFER_H__

#include <pcap.h>
#include <sys/socket.h>

void listdevices(void);
void processpacket(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
void capturepacket(char *device);
void deviceinfo(pcap_if_t *device);
void devicedatalinks(pcap_t *handle);
char* pcapversion(pcap_t *handle);
pcap_t* gethandle(const char *device);
void packetstats(pcap_t * handle);
int* lookupdevice(const char *device);
void filterprogram(pcap_t *handle, bpf_u_int32 mask);


#endif