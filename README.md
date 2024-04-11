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
├─ .git                                                            //
│  ├─ COMMIT_EDITMSG                                               //
│  ├─ HEAD                                                         //
│  ├─ branches                                                     //
│  ├─ config                                                       //
│  ├─ description                                                  //
│  ├─ hooks                                                        //
│  ├─ index                                                        //
│  ├─ info                                                         //
│  │  └─ exclude                                                   //
│  ├─ logs                                                         //
│  │  ├─ HEAD                                                      //
│  │  └─ refs                                                      //
│  │     ├─ heads                                                  //
│  │     │  └─ main                                                //
│  │     └─ remotes                                                //
│  │        └─ origin                                              //
│  │           ├─ HEAD                                             //
│  │           └─ main                                             //
│  ├─ objects                                                      //
│  │  ├─ 03                                                        //
│  │  │  └─ 4a5246e05d038fa34456df39bea0b55b89c72c                 //
│  │  ├─ 09                                                        //
│  │  │  └─ b0cd05f54c8472833de11f01b15375e470577f                 //
│  │  ├─ 0a                                                        //
│  │  │  └─ c676e6ca0310f0ad50397dce8fc83f610c48c3                 //
│  │  ├─ 17                                                        //
│  │  │  └─ 04038e67fc11aad2e8ee9542de5b0ea7b9e013                 //
│  │  ├─ 33                                                        //
│  │  │  └─ ecf5016e1371a114c492465981043e51030ce2                 //
│  │  ├─ 45                                                        //
│  │  │  └─ 71308c198d0d768fd8a7cd39b889fd00cb7517                 //
│  │  ├─ 83                                                        //
│  │  │  └─ d9792c62f68210c1bdc2939a03873fe431d75c                 //
│  │  ├─ 8e                                                        //
│  │  │  └─ 9a0cdace35f160a2629bc0b3904db144918b23                 //
│  │  ├─ 97                                                        //
│  │  │  └─ bb951ae8a87cb323b2667edc85a887592d8526                 //
│  │  ├─ bd                                                        //
│  │  │  └─ daadb548b1e0ec74eb9190d37fe86d41664477                 //
│  │  ├─ c8                                                        //
│  │  │  ├─ a9764717134e00981a9edb3d0c542de821bc9c                 //
│  │  │  └─ c111b423b6b252dcd53db46397bfec7b70b0d0                 //
│  │  ├─ ca                                                        //
│  │  │  └─ 1de9be8d8ca57c8f88e8f710bcd0390ead7352                 //
│  │  ├─ d3                                                        //
│  │  │  └─ bb6cb69a15fb337228ee5cf5efffa42e848497                 //
│  │  ├─ f0                                                        //
│  │  │  └─ 9c53ae5ec9ffac6fcbd9f71428acc0e2643d32                 //
│  │  ├─ fb                                                        //
│  │  │  ├─ 010684965368427a37d897664801a757e4012d                 //
│  │  │  └─ dad13dce9ebb8198b5a7ed3f43961ebd2107b6                 //
│  │  ├─ fd                                                        //
│  │  │  └─ 3ed16a49d0aa6e4a0315344d05ec77d7186c80                 //
│  │  ├─ info                                                      //
│  │  └─ pack                                                      //
│  │     ├─ pack-317952866a5083013b84a84a0c243e369ca5f171.idx      //
│  │     └─ pack-317952866a5083013b84a84a0c243e369ca5f171.pack     //
│  ├─ packed-refs                                                  //
│  └─ refs                                                         //
│     ├─ heads                                                     //
│     │  └─ main                                                   //
│     └─ remotes                                                   //
│        └─ origin                                                 //
│           ├─ HEAD                                                //
│           └─ main                                                //
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
