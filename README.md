# network_sketch


## Environment
Ubuntu22.04

Git commit message template with .stCommitMsg

How to use:

./pcap_analysis 0

## Notice
1. big endian or little endian

2. ip 8-bits reverse

3. "CAIDA anonymized internet traces" no ethnet header, needed to cancel "fseek(pFile, 14, SEEK_CUR);"

4. change IO file path

const char *Pcap_path = "./traces/trace1.pcap";

const char *OutB_path = "./INFO/binary.dat";

const char *Output_path = "./INFO/pcap_result.txt";

const char *OutTxt_path = "./INFO/trace.txt";

5. test.pcap: with ethnet, trace1.pcap: without ethnet


## License
MIT License
