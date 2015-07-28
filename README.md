# ip-analyzer
Analyze IPv4 and IPv6 addresses inside text files, like configurations, logs etc
Usage: ip.pl --files file1,file2,file3, ... ,file[n] {--delimeter [delimeter character]} {--ip-version [4|6]}

The script creates a report for each IP that parses inside the files, the report contains usefull for troubleshooting info like:
* Type of the IP address
* Short, binary and integer representation
* The IP mask
* The size of the IP prefix/subnet
* The last IP address of the prefix/subnet
* Length in bits
* Checks if the ip is loopback, link-local, multicast, unroutable, testnet, anycast
