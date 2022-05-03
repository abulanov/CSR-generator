from scapy.all import *
from scapy.contrib import gtp
from scapy.contrib.gtp_v2 import *
from random import getrandbits, randrange
from ipaddress import IPv4Address, IPv4Network, AddressValueError
from multiprocessing import Process
import argparse
import logging
import re
import time
import yaml


parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", help="Interface through which the packets will be sent")
parser.add_argument("pgw_ip", help="Destination IP address of S5 interface on PGW")
parser.add_argument("num", help="The number of packets to be sent", type=int, default=10, nargs="?")
parser.add_argument("-a", "--apn", help="APN name")
parser.add_argument("-p", "--plmn", help="PLMN ID")
parser.add_argument("-r", "--run", help="Number of running processes: 1, 2, 4, 8", type=int, default=1)
parser.add_argument("-f", "--filename", help="Configuration file in yaml")
parser.add_argument("-s", "--source", help="ip net sourcing the packets", default="10.0.0.0/8")
args = parser.parse_args()

try:
    if args.filename is not None:
        with open(args.filename) as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
except FileNotFoundError:
    logging.error(f"File {args.filename} not found")
    exit(1)

try:
    assert IPv4Address(args.pgw_ip)
except AddressValueError:
    logging.error(f"Wrong PGW IP address: {args.pgw_ip} ")
    exit(1)


if args.run not in (1,2,4,8):
    logging.error(f"Wrong number of running processes: {args.run}, should be 1,2,4 or 8")
    exit(1)


def assign(argname):
    try:
        return argsdict[argname] if argsdict[argname] is not None else config[argname]
    except (KeyError, NameError):
        logging.error(f"{argname} must be defined either via argument or via config file. Refer --help")
        exit(1)


pgw_ip = args.pgw_ip
num = args.num
argsdict = vars(args)
interface = assign("interface")
apn = assign("apn")
apn_length = len(apn) + 1
plmn = assign("plmn")

if not re.search("^\d{5,6}$", plmn):
    logging.error(f"Wrong PLMN ID: {plmn}")
    exit(1)

mcc = plmn[:3]
mnc = plmn[3:]
source = assign("source")
run = assign("run")


base_pkt = (
    IP(
        version=4,
        ihl=5,
        tos=0,
        id=0,
        flags=0,
        frag=0,
        ttl=255,
        proto=17,
        src="192.168.134.129",
        dst=pgw_ip,
    )
    / UDP(sport=36368, dport=2123, chksum=0)
    / GTPHeader(
        seq=5667214,
        version=2,
        P=0,
        T=1,
        MP=0,
        SPARE1=0,
        SPARE2=0,
        gtp_type=32,
        teid=0,
        SPARE3=0,
    )
    / GTPV2CreateSessionRequest(
        IE_list=[
            IE_IMSI(ietype=1, length=8, CR_flag=0, instance=0, IMSI="2500111111111111"),
            IE_MSISDN(ietype=76, length=6, CR_flag=0, instance=0, digits="79161111111"),
            IE_MEI(ietype=75, length=8, CR_flag=0, instance=0, MEI="3584311111111111"),
            IE_ULI(
                ietype=86,
                length=13,
                CR_flag=0,
                instance=0,
                SPARE=0,
                LAI_Present=0,
                ECGI_Present=1,
                TAI_Present=1,
                RAI_Present=0,
                SAI_Present=0,
                CGI_Present=0,
                TAI=ULI_TAI(MCC=mcc, MNC=mnc, TAC=15404),
                ECGI=ULI_ECGI(MCC=mcc, MNC=mnc, SPARE=0, ECI=176130090),
            ),
            IE_ServingNetwork(
                ietype=83, length=3, CR_flag=0, instance=0, MCC=mcc, MNC=mnc
            ),
            IE_RAT(ietype=82, length=1, CR_flag=0, instance=0, RAT_type=6),
            IE_FTEID(
                ietype=87,
                length=9,
                CR_flag=0,
                instance=0,
                ipv4_present=1,
                ipv6_present=0,
                InterfaceType=6,
                GRE_Key=0x00000000,
                ipv4="192.168.134.129",
            ),
            IE_APN(ietype=71, length=apn_length, CR_flag=0, instance=0, APN=apn),
            IE_SelectionMode(
                ietype=128, length=1, CR_flag=0, instance=0, SPARE=0, SelectionMode=0
            ),
            IE_PDN_type(
                ietype=99, length=1, CR_flag=0, instance=0, SPARE=0, PDN_type=3
            ),
            IE_PAA(
                ietype=79,
                length=22,
                CR_flag=0,
                instance=0,
                SPARE=0,
                PDN_type=3,
                ipv6_prefix_length=0,
                ipv6=0x0,
                ipv4="0.0.0.0",
            ),
            IE_Indication(ietype=77, length=7, CR_flag=0, instance=0, DAF=1, PS=1),
            IE_APN_Restriction(
                ietype=127, length=1, CR_flag=0, instance=0, APN_Restriction=0
            ),
            IE_AMBR(
                ietype=72,
                length=8,
                CR_flag=0,
                instance=0,
                AMBR_Uplink=314573,
                AMBR_Downlink=314573,
            ),
            IE_PCO(
                ietype=78,
                length=50,
                CR_flag=0,
                instance=0,
                Extension=1,
                SPARE=0,
                PPP=0,
                Protocols=[
                    PCO_IPCP(
                        length=16,
                        PPP=PCO_PPP(
                            Code=1,
                            Identifier=0,
                            length=16,
                            Options=[
                                PCO_Primary_DNS(length=6, address="0.0.0.0"),
                                PCO_Secondary_DNS(length=6, address="0.0.0.0"),
                            ],
                        ),
                    ),
                    PCO_DNS_Server_IPv4(length=0),
                    PCO_DNS_Server_IPv6(length=0),
                    PCO_IP_Allocation_via_NAS(length=0),
                    PCO_SOF(length=0),
                    PCO_IPv4_Link_MTU_Request(length=0),
                    PCO_PasswordAuthentificationProtocol(
                        length=12,
                        PPP=PCO_PPP_Auth(
                            Code=1,
                            Identifier=0,
                            length=12,
                            PeerID_length=3,
                            PeerID="mts",
                            Password_length=3,
                            Password="mts",
                        ),
                    ),
                ],
            ),
            IE_BearerContext(
                ietype=93,
                length=44,
                CR_flag=0,
                instance=0,
                IE_list=[
                    IE_EPSBearerID(ietype=73, length=1, CR_flag=0, instance=0, EBI=5),
                    IE_FTEID(
                        ietype=87,
                        length=9,
                        CR_flag=0,
                        instance=2,
                        ipv4_present=1,
                        ipv6_present=0,
                        InterfaceType=4,
                        GRE_Key=0xD56DC018,
                        ipv4="192.168.134.129",
                    ),
                    IE_Bearer_QoS(
                        ietype=80,
                        length=22,
                        CR_flag=0,
                        instance=0,
                        SPARE1=0,
                        PCI=1,
                        PriorityLevel=3,
                        SPARE2=0,
                        PVI=0,
                        QCI=9,
                        MaxBitRateForUplink=0,
                        MaxBitRateForDownlink=0,
                        GuaranteedBitRateForUplink=0,
                        GuaranteedBitRateForDownlink=0,
                    ),
                ],
            ),
            IE_UE_Timezone(
                ietype=114, length=2, CR_flag=0, instance=0, Timezone=130, DST=0
            ),
            IE_ChargingCharacteristics(
                ietype=95,
                length=2,
                CR_flag=0,
                instance=0,
                ChargingCharacteristric=0x800,
            ),
        ]
    )
)


def profile(func):
    def wrap(*args, **kwargs):
        started_at = time.time()
        result = func(*args, **kwargs)
        logging.warning(time.time() - started_at)
        return result

    return wrap


def randIP(pref="10.0.0.0/24"):

    subnet = IPv4Network(pref)
    bits = getrandbits(subnet.max_prefixlen - subnet.prefixlen)
    addr = IPv4Address(subnet.network_address + bits)
    addr_str = str(addr)


def getNextIP(pref="10.0.0.0/24"):
    try:
        net = IPv4Network(pref)
    except AddressValueError:
        logging.error(f"Wrong source IP network defined: {pref}")
        exit(1)
    except ValueError:
        logging.error(f"Not an IP prefix. Host bits set: {pref}")
        exit(1)
    addr = IPv4Network(net).hosts()
    while True:
        try:
            yield next(addr)
        except StopIteration:
            addr = IPv4Network(net).hosts()
            yield next(addr)

def getNext(item):
    nextItem = item
    while True:
        nextItem += 1
        yield nextItem

data_iters = list()
for i in range(run):
    data_iters.append(dict())
    data_iters[i]['imsi'] = getNext(int(plmn + f'{i}0000000000'))
    data_iters[i]['msisdn'] = getNext(int(f'7916{i}000000'))
    data_iters[i]['imei'] = getNext(int(f'358436{i}000000000'))
sport = getNext(32000)  # not more than 32000, Code doesn't check it.
seq = getNext(10000000)
gre_key = getNext(1000000000)


def composeCSReq(base_pkt,srcnet,data_iter):
    pkt = base_pkt
    pkt.src = next(srcnet)
    pkt.sport = next(sport)
    pkt.seq = next(seq)
    pkt.IE_list[0].fields["IMSI"] = str(next(data_iter['imsi']))
    pkt.IE_list[1].fields["digits"] = str(next(data_iter['msisdn']))
    pkt.IE_list[2].fields["MEI"] = str(next(data_iter['imei']))
    pkt.IE_list[6].fields["GRE_Key"] = next(gre_key)
    pkt.IE_list[6].fields["ipv4"] = pkt.src
    pkt.IE_list[15].fields["IE_list"][1].fields["GRE_Key"] = next(gre_key)
    pkt.IE_list[15].fields["IE_list"][1].fields["ipv4"] = pkt.src
    return pkt


@profile
def fire(num, srcnet, data_iter):
    src = getNextIP(srcnet)
    try:
        s = conf.L3socket(iface=interface)
    except OSError:
        logging.error(f"No such interface: {interface}")
        exit(1)
    for _ in range(num):
        s.send(composeCSReq(base_pkt,src,data_iter))
    return 1
def main():
    subnets=IPv4Network(source).subnets({1:0, 2:1, 4:2, 8:3}[run])
    for i in range(run):
        subnet=next(subnets)
        logging.warning(f'Starting process: {i}')
        Process(target=fire, args=(num//run,subnet,data_iters[i])).start()
    

if __name__ == '__main__':
    main()
