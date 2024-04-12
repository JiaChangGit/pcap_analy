# pcap_analy


## Environment
Ubuntu22.04, g++ (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, python3.10.12-64bits

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

SaveFigPath = "./INFO/same3D_scatter.png"

SaveFigPath2 = "./INFO/bar.png"

5. test.pcap: with ethernet, trace1.pcap: without ethernet


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
│  ├─ pcap_result.txt                                              //
│  ├─ binary.dat                                                   //
│  ├─ same3D_scatter.png                                           //
│  └─ trace.txt                                                    //
├─ LICENSE                                                         //
├─ README.md                                                       //
├─ docs                                                            //
│  ├─ header.md                                                    //
│  └─ ipReverse.md                                                 //
├─ pcap_analysis.cpp                                               //
├─ static.py                                                       //
└─ traces                                                          //
   ├─ test.pcap                                                    //
   └─ trace1.pcap                                                  //

```


## License
MIT License
