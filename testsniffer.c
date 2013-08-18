#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <assert.h>
#include "sniffer.h"
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>

void testpassed(){
	printf("All tests have been passed successfully\n");
}

void testListDevices(){
	/*int actual = strcmp(listdevices(), "eth0");
	int expected = 0;
	assert(actual == expected);
	testpassed();*/
	listdevices();
}


int main(void){

	char *device = "eth0";
	if(getuid() != 0){
		setuid((uid_t)0) != 0;
		if(errno)
			perror("ERROR:");
	}
	pcap_t *handle;
	handle = gethandle("eth0");
	//listdevices();
	lookupdevice(device);
	//testListDevices();
	//devicedatalinks(handle);
	//capturepacket("eth0");
	//packetstats(handle);

	

	return 0;
}