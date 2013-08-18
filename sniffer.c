#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "sniffer.h"

#define handle_error(msg) \
	do{fprintf(stderr, "ERROR:%s\n", msg); exit(1);} while(0)

#define MAXTOCAPTURE 2383

void processpacket(u_char *user, const struct pcap_pkthdr *header, const u_char *packet){

	int *counter = (int *)user;
	int i;

	printf("Packet count: %d\n", ++(*counter));
	printf("Packet size: %d\n", header->len);
	printf("Payload: ");
	for(i = 0; i < header->len; i++){
		if(isprint(packet[i])){
			printf("%c", packet[i]);
		}
		else
		{
			printf(". ");
		}
		if( (i%16 == 0 && i != 0) || i == header->len - 1)
		{
			printf("\n");
		}
	}
	return;


}
void deviceinfo(pcap_if_t *device){
	printf("name: %s\n", device->name);
	printf("description: %s\n", device->description);
	printf("***************************\n");

}

void listdevices(void){

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t **alldevsp;
	if(pcap_findalldevs(alldevsp, errbuf) == -1){
		fprintf(stderr, "Error:%s\n", errbuf);
		exit(1);
	}
	while(*(alldevsp) != NULL)
	{
		deviceinfo(*alldevsp);
		//printf("%s\n", (*alldevsp)->name);
		*(alldevsp) = (*alldevsp)->next;
	}
	pcap_freealldevs(*alldevsp);
}
/* it appears impossible to retrieve the datalinks */
void devicedatalinks(pcap_t *handle){
	int ret, i;
	int **dl_buff;
	ret = pcap_list_datalinks(handle, dl_buff);
	if(ret == -1)
		handle_error(pcap_geterr(handle));
	for(i = 0; i < ret; i++){
		printf("%s\n", (char*)(*dl_buff+i));
	}
}
pcap_t* gethandle(const char *device){
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	/* pcap_create doesn't work in pcap version < 1.0 
	use pcap_openlive as alternative*/
	handle = pcap_create(device, errbuf);
	if(pcap_activate(handle) != 0){
		fprintf(stderr, "ERROR:%s\n", "Couldn't activate pcap descriptor");
	}else{
	handle = pcap_open_live(device, MAXTOCAPTURE, 1, 512, errbuf);
	if(handle == NULL)
		handle_error("pcap_openlive failed\n");
	}

	return handle;
}

char* pcapversion(pcap_t* handle){
	/* pcap_libray_version doesn't work
	also doesn't possess a manual. weird!! */
	//return pcap_library_version(handle);
	return NULL;
}

void packetstats(pcap_t * handle){
	struct pcap_stat *ps;
	int ret;
	ret = pcap_stats(handle, ps);
	if(ret == -1)
		handle_error("Failed to get statistics");
	/* statistics */
	printf("********** statistics *************\n");
	printf("#packets received:%d\n",ps->ps_recv);
	printf("#packets dropped(by OS):%d\n",ps->ps_drop);
	printf("#packets dropped(by interface or driver):%d\n",ps->ps_ifdrop);
	printf("**************************************\n");
}

/* return network mask */
int* lookupdevice(const char* device){
	bpf_u_int32 *ip;
	bpf_u_int32 *mask;
	char errbuf[PCAP_ERRBUF_SIZE];
	if(pcap_lookupnet(device, ip, mask, errbuf) == -1)
		handle_error(errbuf);
	printf("ip: %d\n", *ip);
	printf("mask: %d\n", *mask);

	return mask;
}
/* create and sets filter program */
void filterprogram(pcap_t *handle, bpf_u_int32 mask){
	struct bpf_program *filter;
	/*set http filter */
	char *filter_string = "tcp port 80";
	if(pcap_compile(handle, filter, filter_string, 0, mask) == -1)
		handle_error(pcap_geterr(handle));

	/*set filter*/
	if(pcap_setfilter(handle, filter) == -1)
		handle_error(pcap_geterr(handle));
}

/* pointer function passed to pcap_loop to process packet */
 void got_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
 {	
 	const char* payload;
 		/* Ethernet header */

 		/* wifi header */

 		/* ip header */

 		/* TCP header */


 }

void capturepacket(char *device){

	/* set the error buffer */
	char errbuf[PCAP_ERRBUF_SIZE];
	memset(errbuf,0,PCAP_ERRBUF_SIZE);
	pcap_t *descr = NULL;
	int count = 0;
	/* we first need a device to capture on */

	/*if ((device = pcap_lookupdev(errbuf) == NULL)){
	fprintf(stderr, "ERROR: %s\n", errbuf);
	exit(1);
	}*/

	/* any/NULL is used to specify to pcap to get packets from
	all interface. PS: cannot set promisc mode with 'any' set */
	//device = NULL;
	

	printf("Opening device %s...\n", device);

	/* open device in promiscuous mode */
	if((descr = pcap_open_live(device, MAXTOCAPTURE, 1, 512, errbuf)) == NULL){
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(1);
	}

	int cansetrfmon = pcap_can_set_rfmon(descr);
	if(cansetrfmon == 1)
		printf("can set rfmon\n");
	else
		printf("cannot set rfmon\n");

	/* loop forever and process each packet received */
	if(pcap_loop(descr, -1, processpacket, (u_char *)&count) == -1){
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr));
		exit(1);
	}

}