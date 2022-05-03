# CSR-generator
## Installation
```
make install
```
## Help

```
# python3 csr_generator.py -h
usage: csr_generator.py [-h] [-i INTERFACE] [-a APN] [-p PLMN] [-r RUN] [-f FILENAME] [-s SOURCE] pgw_ip [num]

positional arguments:
  pgw_ip                Destination IP address of S5 interface on PGW
  num                   The number of packets to be sent

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Interface through which the packets will be sent
  -a APN, --apn APN     APN name
  -p PLMN, --plmn PLMN  PLMN ID
  -r RUN, --run RUN     Number of running processes: 1, 2, 4, 8
  -f FILENAME, --filename FILENAME
                        Configuration file in yaml
  -s SOURCE, --source SOURCE
                        ip net sourcing the packets

```

## Running the script
Comand line arguments overwite values from the config file
```
# python3 csr_generator.py 192.168.1.1 20 -i ens33 -a inet.ry -f config -r 2
WARNING:root:Starting process: 0
WARNING:root:Starting process: 1
WARNING:root:0.11472606658935547
WARNING:root:0.11924934387207031
```

## Expected result
```
# tshark -i ens33 -Y'udp.port==2123' -T 'fields' -e 'ip.src' -e 'udp.srcport' -e 'gtpv2.seq' -e 'e212.imsi'  -e 'e164.msisdn'  -e 'gtpv2.mei' -e 'gtpv2.f_teid_gre_key' -e 'gtpv2.f_teid_ipv4' -e 'gtpv2.apn' -c 20
Running as user "root" and group "root". This could be dangerous.
Capturing on 'ens33'
10.0.0.1	32001	0x00989681	2500100000000001	79160000001	3584360000000001	0x3b9aca01,0x3b9aca02	10.0.0.1,10.0.0.1	inet.ry
10.0.0.2	32002	0x00989682	2500100000000002	79160000002	3584360000000002	0x3b9aca03,0x3b9aca04	10.0.0.2,10.0.0.2	inet.ry
10.128.0.1	32001	0x00989681	2500110000000001	79161000001	3584361000000001	0x3b9aca01,0x3b9aca02	10.128.0.1,10.128.0.1	inet.ry
10.0.0.3	32003	0x00989683	2500100000000003	79160000003	3584360000000003	0x3b9aca05,0x3b9aca06	10.0.0.3,10.0.0.3	inet.ry
10.128.0.2	32002	0x00989682	2500110000000002	79161000002	3584361000000002	0x3b9aca03,0x3b9aca04	10.128.0.2,10.128.0.2	inet.ry
10.0.0.4	32004	0x00989684	2500100000000004	79160000004	3584360000000004	0x3b9aca07,0x3b9aca08	10.0.0.4,10.0.0.4	inet.ry
10.128.0.3	32003	0x00989683	2500110000000003	79161000003	3584361000000003	0x3b9aca05,0x3b9aca06	10.128.0.3,10.128.0.3	inet.ry
10.0.0.5	32005	0x00989685	2500100000000005	79160000005	3584360000000005	0x3b9aca09,0x3b9aca0a	10.0.0.5,10.0.0.5	inet.ry
10.128.0.4	32004	0x00989684	2500110000000004	79161000004	3584361000000004	0x3b9aca07,0x3b9aca08	10.128.0.4,10.128.0.4	inet.ry
10.0.0.6	32006	0x00989686	2500100000000006	79160000006	3584360000000006	0x3b9aca0b,0x3b9aca0c	10.0.0.6,10.0.0.6	inet.ry
10.128.0.5	32005	0x00989685	2500110000000005	79161000005	3584361000000005	0x3b9aca09,0x3b9aca0a	10.128.0.5,10.128.0.5	inet.ry
10.0.0.7	32007	0x00989687	2500100000000007	79160000007	3584360000000007	0x3b9aca0d,0x3b9aca0e	10.0.0.7,10.0.0.7	inet.ry
10.128.0.6	32006	0x00989686	2500110000000006	79161000006	3584361000000006	0x3b9aca0b,0x3b9aca0c	10.128.0.6,10.128.0.6	inet.ry
10.0.0.8	32008	0x00989688	2500100000000008	79160000008	3584360000000008	0x3b9aca0f,0x3b9aca10	10.0.0.8,10.0.0.8	inet.ry
10.128.0.7	32007	0x00989687	2500110000000007	79161000007	3584361000000007	0x3b9aca0d,0x3b9aca0e	10.128.0.7,10.128.0.7	inet.ry
```
## TODO
GTP-C echo responder is needed to keep the sessions up continuously.
