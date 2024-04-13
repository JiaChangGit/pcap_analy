#pragma G++ optimize("Ofast,unroll-loops,no-stack-protector,fast-math,inline")
#pragma G++ target( \
    "sse,sse2,sse3,ssse3,sse4,sse4.1,sse4.2,popcnt,abm,mmx,avx,tune=native")
#pragma comment(linker, "/stack:200000000")
#pragma G++ target("f16c")

#pragma G++ diagnostic error "-fwhole-program"
#pragma G++ diagnostic error "-fcse-skip-blocks"
#pragma G++ diagnostic error "-funsafe-loop-optimizations"
#pragma G++ diagnostic error "-std=c++14"

#define IOS                              \
  std::ios_base::sync_with_stdio(false); \
  std::cin.tie(0);                       \
  std::cout.tie(0);

#include <arpa/inet.h>
#include <netinet/in.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
// const std::string PcapPath = "./traces/test.pcap";
const std::string PcapPath = "./traces/trace1.pcap";
const std::string OutputPath = "./INFO/pcap_result.txt";
const char* OutTxtPath = "./INFO/trace.txt";
const std::string OutBPath = "./INFO/binary.dat";
const std::string LoadTestPath = "./INFO/loadTest.txt";

struct time_val {
  int tv_sec;
  int tv_usec;  // microseconds
};

struct pcap_pkthdr {
  struct time_val ts;  // time stamp
  u_int32_t caplen;    // length of portion present
  u_int32_t len;       // length this packet (off wire)
};

struct IPHeader_t {
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
};

struct TCPUDPHeader_t {
  u_int16_t SrcPort;
  u_int16_t DstPort;
};

struct Dim5 {
  u_int32_t SrcIP;
  u_int32_t DstIP;
  u_int16_t SrcPort;
  u_int16_t DstPort;
  u_int8_t Protocol;
  bool operator==(const Dim5& other) const {
    return (SrcIP == other.SrcIP) && (DstIP == other.DstIP) &&
           (SrcPort == other.SrcPort) && (DstPort == other.DstPort) &&
           (Protocol == other.Protocol);
  }
};
#pragma pack(push, 1)
struct Dim5NoAlign {
  u_int32_t SrcIP;
  u_int32_t DstIP;
  u_int16_t SrcPort;
  u_int16_t DstPort;
  u_int8_t Protocol;
  bool operator==(const Dim5NoAlign& other) const {
    return (SrcIP == other.SrcIP) && (DstIP == other.DstIP) &&
           (SrcPort == other.SrcPort) && (DstPort == other.DstPort) &&
           (Protocol == other.Protocol);
  }
};
#pragma pack(pop)

template <typename T>
class PcapProcessor {
 public:
  PcapProcessor(const std::string& _Pcap_path, const std::string& _Output_path,
                const std::string& _OutTxt_path, const std::string& _OutB_path,
                int _eightBitsReverse, int _eth)
      : Pcap_path(_Pcap_path),
        Output_path(_Output_path),
        OutTxt_path(_OutTxt_path),
        OutB_path(_OutB_path),
        eightBitsReverse(_eightBitsReverse),
        eth(_eth) {}

  size_t processPcap() {
    pcap_pkthdr ptk_header;
    IPHeader_t ip_header;
    TCPUDPHeader_t tcpudp_header;
    T dim5;
    T dim5_tmp;

    FILE* pFile = fopen(Pcap_path.c_str(), "r");
    if (pFile == NULL) {
      std::cerr << "[ERROR] Can not open PCAP file!!\n";
      exit(-1);
    }

    std::ofstream output(Output_path);
    std::ofstream outTxt(OutTxt_path);
    std::fstream outB(OutB_path,
                      std::ios::out | std::ios::in | std::ios::binary);
    if (!outB.is_open()) {
      std::cerr << "Create  \"" << OutB_path
                << "\"  first!! Otherwise, no binary file will be created.\n";
    }

    output << "index    sip               dip           sport     dport      "
              "protocol\n";

    long int pkt_offset = 24;  // pcap header 24 bytes
    size_t index = 0;

    while (true) {
      fseek(pFile, pkt_offset, SEEK_SET);
      memset(&ptk_header, 0, sizeof(pcap_pkthdr));
      memset(&dim5, 0, sizeof(T));
      memset(&dim5_tmp, 0, sizeof(T));
      ++index;

      if (fread(&ptk_header, 16, 1, pFile) != 1) {
        std::cerr << "index: " << index << " can not read ptk_header\n";
        break;
      }

      pkt_offset += 16 + ptk_header.caplen;
      // 14 bytes: ethnet size = src mac (48 bits) + dst mac (48 bits) + type
      // (16 bits) CAIDA no this one
      if (eth != 0) {
        fseek(pFile, 14, SEEK_CUR);
      }

      memset(&ip_header, 0, sizeof(IPHeader_t));
      if (fread(&ip_header, sizeof(IPHeader_t), 1, pFile) != 1) {
        std::cerr << "index: " << index << " can not read ip_header\n";
        break;
      }

      memset(&tcpudp_header, 0, sizeof(TCPUDPHeader_t));
      if (fread(&tcpudp_header, sizeof(TCPUDPHeader_t), 1, pFile) != 1) {
        std::cerr << "index: " << index << " can not read tcpudp_header\n";
        break;
      }

      dim5.SrcIP = ip_header.SrcIP;
      dim5.DstIP = ip_header.DstIP;
      dim5.Protocol = ip_header.Protocol;
      dim5.SrcPort = tcpudp_header.SrcPort;
      dim5.DstPort = tcpudp_header.DstPort;

      char tempSrcIp[256];
      char tempDstIp[256];
      inet_ntop(AF_INET, &(ip_header.SrcIP), tempSrcIp, sizeof(tempSrcIp));
      inet_ntop(AF_INET, &(ip_header.DstIP), tempDstIp, sizeof(tempDstIp));

      dim5.SrcPort = ntohs(dim5.SrcPort);
      dim5.DstPort = ntohs(dim5.DstPort);
      dim5.SrcIP = ntohl(dim5.SrcIP);
      dim5.DstIP = ntohl(dim5.DstIP);

      output << index << "\t" << tempSrcIp << "\t" << tempDstIp << "\t"
             << dim5.SrcPort << "\t" << dim5.DstPort << "\t"
             << unsigned(dim5.Protocol) << "\n";
      output << index << "\t" << dim5.SrcIP << "\t" << dim5.DstIP << "\t"
             << dim5.SrcPort << "\t" << dim5.DstPort << "\t"
             << unsigned(dim5.Protocol) << "\n";

      outTxt << dim5.SrcIP << " " << dim5.DstIP << " " << dim5.SrcPort << " "
             << dim5.DstPort << " " << unsigned(dim5.Protocol) << "\n";

      if (eightBitsReverse == 0) {
        dim5.SrcPort = htons(dim5.SrcPort);
        dim5.DstPort = htons(dim5.DstPort);
        dim5.SrcIP = htonl(dim5.SrcIP);
        dim5.DstIP = htonl(dim5.DstIP);
      }

      // write dat test
      outB.write(reinterpret_cast<const char*>(&dim5), sizeof(T));
      outB.seekg(-1 * static_cast<int>(sizeof(T)), std::ios::cur);
      outB.read(reinterpret_cast<char*>(&dim5_tmp), sizeof(T));

      if (eightBitsReverse == 0) {
        dim5_tmp.SrcPort = htons(dim5_tmp.SrcPort);
        dim5_tmp.DstPort = htons(dim5_tmp.DstPort);
        dim5_tmp.SrcIP = ntohl(dim5_tmp.SrcIP);
        dim5_tmp.DstIP = ntohl(dim5_tmp.DstIP);
      }
      output << "======== convert TEST ========\n";
      output << index << "    " << unsigned(dim5_tmp.SrcIP) << "     "
             << unsigned(dim5_tmp.DstIP) << "      "
             << unsigned(dim5_tmp.SrcPort) << "     "
             << unsigned(dim5_tmp.DstPort) << "      "
             << unsigned(dim5_tmp.Protocol) << "\n";
      output << "==============================\n\n\n";
    }

    fclose(pFile);
    return index - 1;
  }

 private:
  std::string Pcap_path;
  std::string Output_path;
  std::string OutTxt_path;
  std::string OutB_path;
  int eightBitsReverse;
  int eth;
};

template <typename T>
class DataHandler {
 public:
  DataHandler(size_t _originSize) : originSize(_originSize) {}
  void load(const std::string& outTxtPath) {
    std::ifstream file(outTxtPath);
    std::string line;

    unsigned tmp[5];
    T dim;
    while (std::getline(file, line)) {
      std::istringstream iss(line);
      if (!(iss >> tmp[0] >> tmp[1] >> tmp[2] >> tmp[3] >> tmp[4])) {
        std::cerr << "Error reading line: " << line << "\n";
        break;
      }
      dim.SrcIP = tmp[0];
      dim.DstIP = tmp[1];
      dim.SrcPort = tmp[2];
      dim.DstPort = tmp[3];
      dim.Protocol = tmp[4];
      bool found = false;
      for (auto& it : uniqV) {
        if (it.first == dim) {
          ++it.second;
          found = true;
          break;
        }
      }
      if (!found) {
        uniqV.emplace_back(dim, 1);
      }
    }
  }
  void print(const std::string& loadTestPath) {
    std::ofstream file(loadTestPath);
    file << "originSize: " << originSize << "    "
         << "uniqsize: " << uniqV.size() << "\n";
    file << "SIP DIP  SP   DP    PROT     NUM: "
         << "\n\n";
    size_t counter = 0;
    for (const auto& it : uniqV) {
      file << unsigned(it.first.SrcIP) << " " << unsigned(it.first.DstIP)
           << "  " << unsigned(it.first.SrcPort) << "   "
           << unsigned(it.first.DstPort) << "    "
           << unsigned(it.first.Protocol) << "     " << unsigned(it.second)
           << "\n";
      counter = counter + it.second;
    }
    if (counter != originSize) {
      std::cerr << "Error counter: " << counter
                << " / originSize: " << originSize << "\n";
    }
  }

 private:
  std::vector<std::pair<T, size_t>> uniqV;
  size_t originSize;
};

int main(int argc, char** argv) {
  IOS;
  int eightBitsReverse = 0, alignment = 0, eth = 0;
  size_t vSize;
  if (argc != 4) {
    argv[0] = const_cast<char*>("0");
    argv[1] = const_cast<char*>("0");
    argv[2] = const_cast<char*>("0");
    std::cout << "argc != 4\n";
    std::cout << "Usage:  <eightBitsReverse = 0 (default)>\n";
    std::cout << "Usage:  <no alignment = 0 (default)>\n";
    std::cout << "Usage:  <no ethernet = 0 (ex: CAIDA) (default)>\n";
  } else {
    eightBitsReverse = std::atoi(argv[1]);
    alignment = std::atoi(argv[2]);
    eth = std::atoi(argv[3]);
  }
  if (alignment == 0) {
    PcapProcessor<Dim5NoAlign> processor(PcapPath, OutputPath, OutTxtPath,
                                         OutBPath, eightBitsReverse, eth);
    vSize = processor.processPcap();
    DataHandler<Dim5NoAlign> dataHandler(vSize);
    dataHandler.load(OutTxtPath);
    dataHandler.print(LoadTestPath);

  } else {
    PcapProcessor<Dim5> processor(PcapPath, OutputPath, OutTxtPath, OutBPath,
                                  eightBitsReverse, eth);
    vSize = processor.processPcap();
    DataHandler<Dim5> dataHandler(vSize);
    dataHandler.load(OutTxtPath);
    dataHandler.print(LoadTestPath);
  }

  return 0;
}
