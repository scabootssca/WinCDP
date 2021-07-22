#ifndef _CDPSTRUCTS_H_
#define _CDPSTRUCTS_H_

#include <stdio.h>
#include <stdint.h>

/*
_cdp_tlv_types = {0x0001: "Device ID",
                  0x0002: "Addresses",
                  0x0003: "Port ID",
                  0x0004: "Capabilities",
                  0x0005: "Software Version",
                  0x0006: "Platform",
                  0x0007: "IP Prefix",
                  0x0008: "Protocol Hello",
                  0x0009: "VTP Management Domain",  # CDPv2
                  0x000a: "Native VLAN",    # CDPv2
                  0x000b: "Duplex",        #
                  0x000c: "CDP Unknown command (send us a pcap file)",
                  0x000d: "CDP Unknown command (send us a pcap file)",
                  0x000e: "VoIP VLAN Reply",
                  0x000f: "VoIP VLAN Query",
                  0x0010: "Power",
                  0x0011: "MTU",
                  0x0012: "Trust Bitmap",
                  0x0013: "Untrusted Port CoS",
                  0x0014: "System Name",
                  0x0015: "System OID",
                  0x0016: "Management Address",
                  0x0017: "Location",
                  0x0018: "CDP Unknown command (send us a pcap file)",
                  0x0019: "CDP Unknown command (send us a pcap file)",
                  0x001a: "Power Available"}
 
 */


typedef enum CDPType {
	CDPTypeGeneric = 0x0000,
	CDPTypeDeviceID = 0x0001,
	CDPTypeAddresses = 0x0002,
	CDPTypePortID = 0x0003,
	CDPTypeCapabilities = 0x0004,
	CDPTypeSoftwareVersion = 0x0005,
	CDPTypePlatform = 0x0006,
	CDPTypeVTPMgmtDomain = 0x0009,
	CDPTypeNativeVLAN = 0x000a,
	CDPTypeVoiceVLAN = 0x000e
} CDPType;


#define CDPNameGeneric "Undefined"
#define CDPNameDeviceID "Device ID"
#define CDPNameAddresses "Address"
#define CDPNamePortID "Port ID"
#define CDPNameCapabilities "Capabilities"
#define CDPNameSoftwareVersion "Software Version"
#define CDPNamePlatform "Platform"
#define CDPNameVTPMgmtDomain "VTP Management Domain"
#define CDPNameNativeVLAN "Native VLAN"
#define CDPNameVoiceVLAN "VoIP VLAN"

enum IPProtocolType {
	IPProtocolNLPID = 0x01,
	IPProtocol8022 = 0x02
};

enum IPProtocol {
	IPProtocolIPv4 = 0xcc,
	IPProtocolIPV6 = 0xaaaa030000000800
};

typedef struct CDPHeaderInfo {
	uint8_t dstMac[6];
	uint8_t srcMac[6];
	uint16_t length;
	uint8_t llc[8];
	// Then CDP starts
	uint8_t cdpVersion;
	uint8_t cdpTTL;
	uint16_t cdpChecksum;
	// Then formats start
} CDPHeaderInfo;

typedef struct CDPMsgGeneric {
	enum CDPType type;
	void* cdpStruct;
	struct CDPMsgGeneric* next;
} CDPMsgGeneric;

typedef struct CDPMsgString {
	enum CDPType type;
	uint16_t valueLen;
	char *value;
} CDPMsgString;

typedef struct CDPMsgInterger {
	enum CDPType type;
	uint32_t value;
} CDPMsgInterger;

typedef struct CDPMsgAddress {
	uint8_t protocolType;
	uint8_t protocolLen;
	uint8_t *protocol;
	uint16_t addressLength;
	uint8_t *address;
} CDPMsgAddress;

typedef struct CDPMsgAddressList {
	enum CDPType type;
	uint32_t numAddresses;
	CDPMsgAddress *addresses;
} CDPMsgAddressList;

const char* get_cdp_type_name(uint16_t dataType);
void free_cdp_struct(CDPMsgGeneric* structPtr);
void parse_cdp_value(CDPMsgGeneric* dstPtr, uint16_t dataType, uint16_t dataLen, uint32_t capLen, const uint8_t* pkt_data, uint32_t pkt_data_index);

#endif
