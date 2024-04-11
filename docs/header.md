// pcap header
struct pcap_file_header {
u_int32_t magic;         // 0xa1b2c3d4
u_int16_t version_major; // magjor Version 2
u_int16_t version_minor; // magjor Version 4
int32_t thiszone;        // gmt to local correction
u_int32_t sigfigs;       // accuracy of timestamps
u_int32_t snaplen;       // max length saved portion of each pkt
u_int32_t linktype;      // data link type (LINKTYPE_*)
};

struct time_val {
  int tv_sec;
  int tv_usec; // microseconds
}
;

// packet header
typedef struct pcap_pkthdr {
  struct time_val ts;  // time stamp
  u_int32_t caplen;    // length of portion present
  u_int32_t len;       // length this packet (off wire)
} pcap_pkthdr;

// ip header 20 bytes
typedef struct IPHeader_t {
  u_int8_t Ver_HLen;
  u_int8_t TOS;
  u_int16_t TotalLen;
  u_int16_t ID;
  u_int16_t Flag_Segment;
  u_int8_t TTL;
  u_int8_t Protocol;
  u_int16_t Checksum;
  u_int32_t SrcIP;
  u_int32_t DstIP;
} IPHeader_t;

// TCP, UDP
typedef struct TCPUDPHeader_t {
  u_int16_t SrcPort;
  u_int16_t DstPort;

} TCPUDPHeader_t;
