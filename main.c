#include <stdio.h>
#include <time.h>
#include <string.h>
#include "pcap.h"
#include "cdpStructs.h"

/*
# CDP TLV classes keyed by type
_cdp_tlv_cls = {0x0001: "CDPMsgDeviceID",
                0x0002: "CDPMsgAddr",
                0x0003: "CDPMsgPortID",
                0x0004: "CDPMsgCapabilities",
                0x0005: "CDPMsgSoftwareVersion",
                0x0006: "CDPMsgPlatform",
                0x0008: "CDPMsgProtoHello",
                0x0009: "CDPMsgVTPMgmtDomain",  # CDPv2
                0x000a: "CDPMsgNativeVLAN",    # CDPv2
                0x000b: "CDPMsgDuplex",        #
                #                 0x000c: "CDPMsgGeneric",
                #                 0x000d: "CDPMsgGeneric",
                0x000e: "CDPMsgVoIPVLANReply",
                0x000f: "CDPMsgVoIPVLANQuery",
                0x0010: "CDPMsgPower",
                0x0011: "CDPMsgMTU",
                0x0012: "CDPMsgTrustBitmap",
                0x0013: "CDPMsgUntrustedPortCoS",
                #                 0x0014: "CDPMsgSystemName",
                #                 0x0015: "CDPMsgSystemOID",
                0x0016: "CDPMsgMgmtAddr",
                #                 0x0017: "CDPMsgLocation",
                0x0019: "CDPMsgUnknown19",
                #                 0x001a: "CDPPowerAvailable"
                }
*/

uint16_t swap_byte_order(uint16_t input) {
	return((input & 0x00ff) << 8) | input>>8;
}

CDPMsgGeneric* firstCDPMsg = NULL;
CDPMsgGeneric* currentCDPMsg = NULL;

CDPMsgGeneric* get_cdp_node(CDPType type) {
	currentCDPMsg = firstCDPMsg;
	for (int i=0; i<50; i++) {
		if (currentCDPMsg->type == type) {
			return currentCDPMsg;
		}
		
		//printf("Information Node Type: %d Name: %s\n", currentCDPMsg->type, get_cdp_type_name(currentCDPMsg->type));
		currentCDPMsg = currentCDPMsg->next;
		
		if (currentCDPMsg == NULL) {
			break;
		}
	}
	
	return NULL;
}

void print_cdp_value(CDPMsgGeneric* structPtr) {
	if (structPtr->type == CDPTypeGeneric) {
		return;
	// This struct is a String Type
	} else if (
		structPtr->type == CDPTypeDeviceID ||
		structPtr->type == CDPTypePortID ||
		structPtr->type == CDPTypeSoftwareVersion ||
		structPtr->type == CDPTypePlatform ||
		structPtr->type == CDPTypeVTPMgmtDomain) {
		
		CDPMsgString* stringStruct = (CDPMsgString*)structPtr->cdpStruct;
	
		// We want the software version to have tabs after each \n
		if (structPtr->type == CDPTypeSoftwareVersion) {
			printf("%s:\n\t", get_cdp_type_name(structPtr->type));
			for (int i=0; i<stringStruct->valueLen; i++) {
				putchar(stringStruct->value[i]);
				
				if (stringStruct->value[i] == '\n') {
					putchar('\t');
				}
			}
			printf("\n");
		} else {
			printf("%s:\n\t%s\n", get_cdp_type_name(structPtr->type), stringStruct->value);
		}
	// This struct is a Interger type
	}  else if (
		structPtr->type == CDPTypeNativeVLAN ||
		structPtr->type == CDPTypeVoiceVLAN) {
		printf("%s:\n\t%d\n", get_cdp_type_name(structPtr->type), ((CDPMsgInterger*)structPtr->cdpStruct)->value);
	// This struct is an IP type
	} else if (
		structPtr->type == CDPTypeAddresses) {
		printf("%s:\n", get_cdp_type_name(structPtr->type));
		CDPMsgAddressList* addrListStruct = (CDPMsgAddressList*)structPtr->cdpStruct;
		CDPMsgAddress* addrStruct;
		for (int i=0; i<addrListStruct->numAddresses; i++) {
			addrStruct = &addrListStruct->addresses[i];
			printf("\t");
			for (int x=0; x<addrStruct->addressLength; x++) {
				if (addrStruct->protocolType == IPProtocolNLPID && addrStruct->protocol[0] == IPProtocolIPv4) {
					printf("%s%d", x==0?"":".", addrStruct->address[x]);
				} else {
					printf("%.2x", addrStruct->address[x]);
				}
			}
			printf("\n");
		}
	}
}


void packet_handler(u_char *param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	char timestr[16] = {0};
	struct tm ltime = {};
	time_t local_tv_sec;

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);
	
	printf("\n\n-------------------------------------------------------\n\n");
	printf("Got CDP Packet!\n\n[%s] - Pkt Len: %d - Captured Len: %d\n", timestr, header->len, header->caplen);
	
	/* Print the packet */
	for (int i=1; (i < header->caplen + 1 ) ; i++)
	{
		printf("%.2x ", pkt_data[i-1]);
		if ( (i % 16) == 0) printf("\n");
	}
	
	CDPHeaderInfo *cdpInfo = (CDPHeaderInfo*)pkt_data;
	
	// Fix Byte Orders, Network is Big Endian, Win10 is Little Endian
	cdpInfo->length = swap_byte_order(cdpInfo->length);
	cdpInfo->cdpChecksum = swap_byte_order(cdpInfo->cdpChecksum);

	printf("\n\n-------------------------------------------------------\n\n");
	printf("Dst Mac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", cdpInfo->dstMac[0], cdpInfo->dstMac[1], cdpInfo->dstMac[2], cdpInfo->dstMac[3], cdpInfo->dstMac[4], cdpInfo->dstMac[5]);
	printf("Src Mac: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", cdpInfo->srcMac[0], cdpInfo->srcMac[1], cdpInfo->srcMac[2], cdpInfo->srcMac[3], cdpInfo->srcMac[4], cdpInfo->srcMac[5]);
	printf("Length: %d\n", cdpInfo->length);
	printf("CDP Version: %d\n", cdpInfo->cdpVersion);
	printf("CDP TTL: %d\n", cdpInfo->cdpTTL);
	printf("CDP Checksum: %d\n", cdpInfo->cdpChecksum);
	printf("\n\n");
	
	/* Parse the rest of the packet */
	uint16_t dataType = 0;
	uint16_t dataLen = 0;
	
	uint8_t dataTypeBytes = 0;
	uint8_t dataLenBytes = 0;

	for (uint32_t i=sizeof(CDPHeaderInfo); (i < header->caplen ) ; i++)
	{
		if (dataTypeBytes == 0) {
			dataType = 0;
			dataType |= pkt_data[i]<<8;
			dataTypeBytes++;
		} else if (dataTypeBytes == 1) {
			dataType |= pkt_data[i];
			dataTypeBytes++;
		} else if (dataLenBytes == 0) {
			dataLen = 0;
			dataLen |= pkt_data[i]<<8;
			dataLenBytes++;
		} else if (dataLenBytes == 1) {
			dataLen |= pkt_data[i];
			dataLenBytes++;
		} else {
			//printf("Got Data Type: 0x%04x\n", dataType);
			//printf("Got Data Len:  %d\n", dataLen);

			// This'll parse the CDP info and populate a struct
			CDPMsgGeneric* returnCDPMsg = malloc(sizeof(*returnCDPMsg));
			returnCDPMsg->type = CDPTypeGeneric;
			returnCDPMsg->cdpStruct = NULL;
			returnCDPMsg->next = NULL;

			parse_cdp_value(returnCDPMsg, dataType, dataLen, header->caplen, pkt_data, i);
			
			// First node then save it as such
			if (firstCDPMsg == NULL) {
				firstCDPMsg = returnCDPMsg;
				currentCDPMsg = returnCDPMsg;
			// Else we'll update the pointer
			} else {
				currentCDPMsg->next = returnCDPMsg;
				currentCDPMsg = returnCDPMsg;
			}

			//if (returnCDPMsg->type == CDPTypeGeneric) {
				//printf("Return struct type is undefined.\n");
			//} else {
				//printf("Return struct type is %.2x\n", returnCDPMsg->type);
			//}

			// Do -5 because packet type and len are each 2 bytes and count towards the total data len
			// That means for a 10 byte string the length will be marked as 14 bytes
			// Instead of -4 we do -5 to account for the char we're on at the moment
			i += (dataLen-5);

			//printf("Byte %i: %x\n", dataBytes, pkt_data[i]);
			//printf("\n\n");
			dataTypeBytes = 0;
			dataLenBytes = 0;
		}
				
		//printf("%.2x ", pkt_data[i]);
		//if ( (i % 16) == 0) printf("\n");
	}

	CDPMsgGeneric* infoNode;
	CDPType infoOrder[] = {
		CDPTypeSoftwareVersion,
		CDPTypePlatform,
		CDPTypeDeviceID,
		CDPTypePortID,
		CDPTypeAddresses,
		CDPTypeNativeVLAN,
		CDPTypeVoiceVLAN,
		CDPTypeVTPMgmtDomain
	};

	for (int i=0; i<sizeof(infoOrder)/sizeof(CDPType); i++) {
		infoNode = get_cdp_node(infoOrder[i]);
		if (infoNode != NULL) {
			print_cdp_value(infoNode);
		}
	}
	
	// Now we free memory
	currentCDPMsg = firstCDPMsg;
	while (1) {
		free_cdp_struct(currentCDPMsg);
		currentCDPMsg = currentCDPMsg->next;
		
		if (currentCDPMsg == NULL) {
			break;
		}
	}
	
	firstCDPMsg = NULL;
	currentCDPMsg = NULL;
	
	printf("\n-------------------------------------------------------\n");
}

int main(int argc, char** argv) {
	//const char *pcap_version = pcap_lib_version();
	//printf("%s\n\n", pcap_version);
	// Npcap output: "Npcap version 0.92, based on libpcap version 1.8.1"
	// WinPcap output: "WinPcap version 4.1.3"
	
	printf("Hello, Probing Network Devices.\n");
	
	// First we'll get a list of devices
	pcap_if_t *alldevs;
	pcap_if_t *device;
	int i=0;
	int inum=0;
	pcap_t *deviceHandle;
	struct bpf_program fcode;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		printf("Error in pcap_findalldevs_ex: %s\n", errbuf);
		return 1;
	}
	
	printf("Sucessfully got a list of devices.\n");
	
	// Then print them
	for (device=alldevs; device != NULL; device = device->next) {
		printf("%d. %s", ++i, device->name);
		
		if (device->description) {
			printf(" (%s)\n", device->description);
		} else {
			printf(" (No description available)\n");
		}
	};
	
	// Check to make sure there are actually devices
	if (i == 0) {
		printf("\nNo interfaces found! make sure Npcap is installed.\n");
		return 1;
	}
	
	// Get which device to probe
	printf("Enter the interface number (1-%d): ", i);
	scanf("%d", &inum);
	
	printf("You chose %i\n", inum);
	
	if (inum < 1 || inum > i) {
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return 1;
	}
	
	// Jump to the selected device
	for(device=alldevs, i=0; i< inum-1 ;device=device->next, i++);
	
	// Open the device
	if ( (deviceHandle=pcap_open(
			device->name,
			65536,
			PCAP_OPENFLAG_PROMISCUOUS,
			1000,
			NULL,
			errbuf)) == NULL)
	{
		printf("\nUnable to open the adapter. %s is no supported by Npcap\n", device->name);
		pcap_freealldevs(alldevs);
		return 1;
	}
	
	printf("\nListening on %s...\n", device->description);
		
	// Now we don't need the device list anymore, so free it
	pcap_freealldevs(alldevs);
	
	// Create the CDP filter
	if (pcap_compile(deviceHandle, &fcode, "ether dst 01:00:0c:cc:cc:cc", 1, 0xffffffff) < 0) {
		printf("\nUnable to compile the packet filter.\n");
		return 1;
	}
	
	// Set the CDP filter
	if (pcap_setfilter(deviceHandle, &fcode) < 0) {
		printf("\nError setting the packet filter.\n");
		return 1;
	}
	
	// And start listening
	pcap_loop(deviceHandle, 0, packet_handler, NULL);
	
	scanf("Hit Any Key");
	return 0;
}
