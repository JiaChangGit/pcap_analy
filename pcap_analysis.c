#pragma GCC optimize("Ofast,unroll-loops,no-stack-protector,fast-math,inline")
#pragma GCC target( \
    "sse,sse2,sse3,ssse3,sse4,sse4.1,sse4.2,popcnt,abm,mmx,avx,tune=native")
#pragma comment(linker, "/stack:200000000")
#pragma GCC target("f16c")

#pragma GCC diagnostic error "-fwhole-program"
#pragma GCC diagnostic error "-fcse-skip-blocks"
#pragma GCC diagnostic error "-funsafe-loop-optimizations"
#pragma GCC diagnostic error "-std=c++14"

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// IO file path
const char *Pcap_path = "./traces/trace1.pcap";
const char *Output_path = "./INFO/old_pcap_result.txt";
const char *OutTxt_path = "./INFO/old_trace.txt";
const char *OutB_path = "./INFO/old_binary.dat";

// 儲存轉化的ip地址。
char tempSrcIp[256];
char tempDstIp[256];

struct time_val {
  int tv_sec;
  int tv_usec;  // microseconds
};

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

typedef struct Dim5 {
  u_int32_t SrcIP;
  u_int32_t DstIP;
  u_int16_t SrcPort;
  u_int16_t DstPort;
  u_int8_t Protocol;
} Dim5;

int main(int argc, char *argv[]) {
  int eightBitsReverse = 0;
  if (argc != 2) {
    printf("use default, eightBitsReverse = 0\n");
  }
  eightBitsReverse = argv[1];
  pcap_pkthdr *ptk_header = NULL;
  IPHeader_t *ip_header = NULL;
  TCPUDPHeader_t *tcpudp_header = NULL;
  Dim5 *dim5 = NULL;
  Dim5 *dim5_tmp = NULL;

  // init memory
  ptk_header = (pcap_pkthdr *)malloc(256);
  ip_header = (IPHeader_t *)malloc(sizeof(IPHeader_t));
  tcpudp_header = (TCPUDPHeader_t *)malloc(sizeof(TCPUDPHeader_t));
  dim5 = (Dim5 *)malloc(sizeof(Dim5));
  dim5_tmp = (Dim5 *)malloc(sizeof(Dim5));

  // read file
  // "CAIDA" no ethnet header, Should Del "fseek(pFile, 14, SEEK_CUR);"
  FILE *pFile = fopen(Pcap_path, "r");
  if (pFile == NULL) {
    fprintf(stderr, "[ERROR] Can not open PCAP file!!\n");
    exit(-1);
  }
  FILE *output = fopen(Output_path, "w+");
  if (output == NULL) {
    fprintf(stderr, "[ERROR] Can not write file!!\n");
    exit(-1);
  }
  FILE *outTxt = fopen(OutTxt_path, "w+");
  if (outTxt == NULL) {
    fprintf(stderr, "[ERROR] Can not write txt!!\n");
    exit(-1);
  }
  FILE *outB = fopen(OutB_path, "w+");
  if (outB == NULL) {
    fprintf(stderr, "[ERROR] Can not write dat!!\n");
    exit(-1);
  }

  fprintf(output,
          "index    sip               dip           sport     dport      "
          "protocol\n");

  long int pkt_offset = 24;  // 用來檔案偏移, pcap header 24 bytes
  size_t index = 0;

  while (1) {
    // 移動pfile檔案指針位置，跳過pcap header
    fseek(pFile, pkt_offset, SEEK_SET);
    memset(ptk_header, 0, sizeof(pcap_pkthdr));
    memset(dim5, 0, sizeof(Dim5));
    memset(dim5_tmp, 0, sizeof(Dim5));
    ++index;

    // read packet header 16 bytes
    if (fread(ptk_header, 16, 1, pFile) != 1) {
      fprintf(stderr, "index: %ld can not read ptk_header\n", index);
      break;
    }

    // 下一個packet header開始位置= 起始位置+packet header（16
    // bytes）+數據長度caplen
    pkt_offset += 16 + ptk_header->caplen;

    // printf("caplen:%d\n", ptk_header->caplen);

    // 14 bytes: ethnet size = src mac (48 bits) + dst mac (48 bits) + type (16
    // bits)
    // CAIDA no this one
    // fseek(pFile, 14, SEEK_CUR);

    // IP header 20 bytes
    memset(ip_header, 0, sizeof(IPHeader_t));
    if (fread(ip_header, sizeof(IPHeader_t), 1, pFile) != 1) {
      fprintf(stderr, "index: %ld can not read ip_header\n", index);
      break;
    }

    memset(tcpudp_header, 0, sizeof(TCPUDPHeader_t));
    if (fread(tcpudp_header, sizeof(TCPUDPHeader_t), 1, pFile) != 1) {
      fprintf(stderr, "index: %ld can not read tcpudp_header\n", index);
      break;
    }

    dim5->SrcIP = ip_header->SrcIP;
    dim5->DstIP = ip_header->DstIP;
    dim5->Protocol = ip_header->Protocol;
    dim5->SrcPort = tcpudp_header->SrcPort;
    dim5->DstPort = tcpudp_header->DstPort;

    //  ip variable type changed to char*
    inet_ntop(AF_INET, &(ip_header->SrcIP), tempSrcIp, sizeof(tempSrcIp));
    inet_ntop(AF_INET, &(ip_header->DstIP), tempDstIp, sizeof(tempDstIp));

    // 本函數將一個16位數由網絡字節順序轉換為主機字節順序。
    // 返回值：ntohs()返回一個以主機字節順序表達的數。
    // ntohs: net to host short int 16 bytes
    dim5->SrcPort = ntohs(dim5->SrcPort);
    dim5->DstPort = ntohs(dim5->DstPort);
    // ntohl: net to host long int 32 bytes
    dim5->SrcIP = ntohl(dim5->SrcIP);
    dim5->DstIP = ntohl(dim5->DstIP);

    fprintf(output, "%ld %s %s %d %d %d\n", index, tempSrcIp, tempDstIp,
            dim5->SrcPort, dim5->DstPort, dim5->Protocol);

    fprintf(output, "%ld %u %u %d %d %d\n\n", index, dim5->SrcIP, dim5->DstIP,
            dim5->SrcPort, dim5->DstPort, dim5->Protocol);

    fprintf(outTxt, "%u %u %d %d %d\n", dim5->SrcIP, dim5->DstIP, dim5->SrcPort,
            dim5->DstPort, dim5->Protocol);
    // write dat (binary)
    // htonl: host to net long int 32 bytes
    if (eightBitsReverse == 0) {
      dim5->SrcPort = htons(dim5->SrcPort);
      dim5->DstPort = htons(dim5->DstPort);
      dim5->SrcIP = htonl(dim5->SrcIP);
      dim5->DstIP = htonl(dim5->DstIP);
    }
    fwrite(dim5, sizeof(Dim5), 1, outB);

    // write dat test
    fseek(outB, -1 * sizeof(Dim5), SEEK_CUR);
    fread(dim5_tmp, sizeof(Dim5), 1, outB);
    // ntohl: net to host long int 32 bytes
    if (eightBitsReverse == 0) {
      dim5_tmp->SrcPort = htons(dim5->SrcPort);
      dim5_tmp->DstPort = htons(dim5->DstPort);
      dim5_tmp->SrcIP = ntohl(dim5_tmp->SrcIP);
      dim5_tmp->DstIP = ntohl(dim5_tmp->DstIP);
    }
    fprintf(output, "======== convert TEST ========\n");
    fprintf(output, "%ld %u %u %d %d %d\n", index,
            (unsigned int)dim5_tmp->SrcIP, (unsigned int)dim5_tmp->DstIP,
            dim5_tmp->SrcPort, dim5_tmp->DstPort, dim5_tmp->Protocol);
    fprintf(output, "==============================\n\n\n");
  }

  fclose(pFile);
  fclose(output);
  fclose(outTxt);
  fclose(outB);
  return 0;
}

/*
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
*/
