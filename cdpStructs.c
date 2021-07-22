#include "cdpStructs.h"
#include <stdlib.h>
#include <string.h>

#define CDP_PARSE_DEBUG 0

#define debug_printf(fmt, ...) \
	do { if (CDP_PARSE_DEBUG) printf(fmt, __VA_ARGS__); } while (0)

const char* get_cdp_type_name(uint16_t dataType) {
	switch (dataType) {
		case CDPTypeDeviceID:
			return CDPNameDeviceID;
		case CDPTypeAddresses:
			return CDPNameAddresses;
		case CDPTypePortID:
			return CDPNamePortID;
		case CDPTypeCapabilities:
			return CDPNameCapabilities;
		case CDPTypeSoftwareVersion:
			return CDPNameSoftwareVersion;
		case CDPTypePlatform:
			return CDPNamePlatform;
		case CDPTypeVTPMgmtDomain:
			return CDPNameVTPMgmtDomain;
		case CDPTypeNativeVLAN:
			return CDPNameNativeVLAN;
		case CDPTypeVoiceVLAN:
			return CDPNameVoiceVLAN;
	};
	
	return CDPNameGeneric;
}

void free_cdp_struct(CDPMsgGeneric* structPtr) {
	if (structPtr->type == CDPTypeGeneric) {
		// This struct never got filled out
	} else if (
		structPtr->type == CDPTypeDeviceID ||
		structPtr->type == CDPTypePortID ||
		structPtr->type == CDPTypeSoftwareVersion ||
		structPtr->type == CDPTypePlatform ||
		structPtr->type == CDPTypeVTPMgmtDomain)
	{
		free(((CDPMsgString*)structPtr->cdpStruct)->value);
		// This struct is a String Type
	}  else if (
		structPtr->type == CDPTypeNativeVLAN ||
		structPtr->type == CDPTypeVoiceVLAN)
	{
		// This struct is a Interger type
	} else if (
		structPtr->type == CDPTypeAddresses)
	{
		// This struct is an IP type
		CDPMsgAddressList* addrList = (CDPMsgAddressList*)structPtr->cdpStruct;
		
		for (int i=0; i<addrList->numAddresses; i++) {
			free(addrList->addresses[i].protocol);
			free(addrList->addresses[i].address);
		}
		
		free(addrList->addresses);
	}
	
	free(structPtr->cdpStruct);
}

void parse_cdp_value(CDPMsgGeneric* dstPtr, uint16_t dataType, uint16_t dataLen, uint32_t capLen, const uint8_t* pkt_data, uint32_t pkt_data_index) {
	if (pkt_data_index+dataLen-4 > capLen) { // -4 to account for the dataType and dataLen
		printf("Error, packet data len (Index: %d Offset: -4 DataLen: %d) greater than available info (%d)\n", pkt_data_index, dataLen, capLen);
		return;
	}
	
	if (dataType == CDPTypeDeviceID ||
		dataType == CDPTypePortID ||
		dataType == CDPTypeSoftwareVersion ||
		dataType == CDPTypePlatform ||
		dataType == CDPTypeVTPMgmtDomain)
	{
		CDPMsgString* workingStruct = malloc(sizeof(*workingStruct));
		workingStruct->type = dataType;
		workingStruct->valueLen = dataLen-4;
		workingStruct->value = (char*)calloc(1, dataLen-4+1);
		memset(workingStruct->value, 0, dataLen-4+1);
		strncpy(workingStruct->value, (char*)pkt_data+pkt_data_index, dataLen-4);
		
		dstPtr->cdpStruct = (void*)workingStruct;
		dstPtr->type = workingStruct->type;

		debug_printf("Got %s with value: %s\n", get_cdp_type_name(dataType), workingStruct->value);
	}  else if (dataType == CDPTypeNativeVLAN ||
				dataType == CDPTypeVoiceVLAN)
	{
		CDPMsgInterger* workingStruct = malloc(sizeof(*workingStruct));
		workingStruct->type = dataType;
		
		if (dataType == CDPTypeVoiceVLAN) {
			//uint8_t voiceVlanData = pkt_data[pkt_data_index++];
			pkt_data_index++; // We'll skip the next byte (What's it for?)
		}
		
		workingStruct->value = pkt_data[pkt_data_index]<<8 | pkt_data[pkt_data_index+1];
		pkt_data_index += 2;

		dstPtr->cdpStruct = (void*)workingStruct;
		dstPtr->type = workingStruct->type;

		debug_printf("Got %s with value: %d\n", get_cdp_type_name(dataType), workingStruct->value);
	} else if (dataType == CDPTypeAddresses) {
		CDPMsgAddressList* workingStruct = malloc(sizeof(*workingStruct));
		workingStruct->type = dataType;
		
		dstPtr->cdpStruct = (void*)workingStruct;
		dstPtr->type = workingStruct->type;
		
		workingStruct->numAddresses = (pkt_data[pkt_data_index]<<24) | (pkt_data[pkt_data_index+1]<<16) | (pkt_data[pkt_data_index+2]<<8) | (pkt_data[pkt_data_index+3]<<0); // Gotta reverse endian
		pkt_data_index += 4;
		
		// Allocate space for the addresses
		workingStruct->addresses = (CDPMsgAddress*)malloc(sizeof(CDPMsgAddress)*workingStruct->numAddresses);
		debug_printf("Got %s with %i addresses\n", get_cdp_type_name(dataType), workingStruct->numAddresses);
		
		CDPMsgAddress* addrStruct;
		for (int i=0; i<workingStruct->numAddresses; i++) {
			addrStruct = &(workingStruct->addresses[i]);
			addrStruct->protocolType = pkt_data[pkt_data_index++]; 

			// Extract the protocol of this address
			// Length is 1 byte for NLPID for 802.2 it is either 3 or 8 bytes
			addrStruct->protocolLen = pkt_data[pkt_data_index++];
			addrStruct->protocol = (uint8_t*)malloc(sizeof(uint8_t)*addrStruct->protocolLen);
			
			debug_printf("	Address %i - Type: %i - Protocol: ", i, addrStruct->protocolType);
			
			for (int x=0; x<addrStruct->protocolLen; x++) {
				addrStruct->protocol[x] = pkt_data[pkt_data_index++];
				debug_printf("%02x", addrStruct->protocol[x]);
			}
			
			// Now we extract the address and allocate space for it
			addrStruct->addressLength = (pkt_data[pkt_data_index]<<8) | pkt_data[pkt_data_index+1];
			pkt_data_index += 2;
			
			addrStruct->address = (uint8_t*)malloc(sizeof(uint8_t)*addrStruct->addressLength);
			debug_printf("%s", " - Address: ");
			
			for (int x=0; x<addrStruct->addressLength; x++) {
				addrStruct->address[x] = pkt_data[pkt_data_index++];
				if (addrStruct->protocolType == IPProtocolNLPID && addrStruct->protocol[0] == IPProtocolIPv4) {
					debug_printf("%s%d", x==0?"":".", addrStruct->address[x]);
				} else {
					debug_printf("%.2x", addrStruct->address[x]);
				}
			}

			debug_printf("%s", "\n");
		}
	}
}
