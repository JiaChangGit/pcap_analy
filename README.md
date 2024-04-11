# pcap_analy


## Environment
Ubuntu22.04

Git commit message template with .stCommitMsg


## Notice
1. big endian or little endian

2. ip 8-bits reverse

3. "CAIDA anonymized internet traces" no ethnet header, needed to cancel "fseek(pFile, 14, SEEK_CUR);"

4. change IO file path

  pcap_analysis.cpp:

const std::string PcapPath = "./traces/trace1.pcap";

const std::string OutputPath = "./INFO/pcap_result.txt";

const std::string OutTxtPath = "./INFO/trace.txt";

const std::string OutBPath = "./INFO/binary.dat";

const std::string LoadTestPath = "./INFO/loadTest.txt";


  static.py:

ReadPath = "./INFO/trace.txt"

SaveFigPath = "./INFO/unique3D_scatter.png"


  pcap_analysis.c:

const char *Pcap_path = "./traces/trace1.pcap";

const char *Output_path = "./INFO/old_pcap_result.txt";

const char *OutTxt_path = "./INFO/old_trace.txt";

const char *OutB_path = "./INFO/old_binary.dat";

5. test.pcap: with ethernet, trace1.pcap: without ethernet

6. static.py: Filter out data with count greater than 1000

high_count_data = plot_data[plot_data['count'] > 1000]


## How to Use

1. check IO path

2. check library (ex: #include <arpa/inet.h>、#include <netinet/in.h>......)

3. check with ethernet, without ethernet

4. run pcap_analysis.cpp first:

g++ "pcap_analysis.cpp" -o "pcap_analysis" && "./pcap_analysis"

5. then run static.py:

python3 static.py


## Project Tree:

```
pcap_analysis                                                      //
├─ .editorconfig                                                   //
├─ .gitattributes                                                  //
├─ .gitignore                                                      //
├─ .mailmap                                                        //
├─ .stCommitMsg                                                    //
├─ INFO                                                            //
│  ├─ loadTest.txt                                                 //
│  ├─ old_pcap_result.txt                                          //
│  ├─ old_trace.txt                                                //
│  ├─ pcap_result.txt                                              //
│  └─ trace.txt                                                    //
├─ LICENSE                                                         //
├─ README.md                                                       //
├─ docs                                                            //
│  ├─ header.md                                                    //
│  └─ ipReverse.md                                                 //
├─ pcap_analysis.c                                                 //
├─ pcap_analysis.cpp                                               //
├─ static.py                                                       //
└─ traces                                                          //
   ├─ test.pcap                                                    //
   └─ trace1.pcap                                                  //

```


## License
MIT License
