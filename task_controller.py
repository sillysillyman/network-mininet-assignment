#!/usr/bin/python3

from scapy.all import *  # you can use scapy in this task
import pox.openflow.libopenflow_01 as of

# KAIST CS341 SDN Lab Task 2, 3, 4
#
# All functions in this file runs on the controller:
#   - init(net):
#       - runs only once for network, when initialized
#       - the controller should process the given network structure for future behavior
#   - addrule(switchname, connection):
#       - runs when a switch connects to the controller
#       - the controller should insert routing rules to the switch
#   - handlePacket(packet, connection):
#       - runs when a switch sends unhandled packet to the controller
#       - the controller should decide whether to handle the packet:
#           - let the switch route the packet
#           - drop the packet
#
# Task 2: Getting familiarized with POX
#   - Let switches "flood" packets
#   - This is not graded
#
# Task 3: Implementing a Simple Routing Protocol
#   - Let switches route via Dijkstra
#   - Match ARP and ICMP over IPv4 packets
#
# Task 4: Implementing simple DNS censorship
#   - Let switches send DNS packets to Controller
#       - By default, switches will send unhandled packets to controller
#   - Drop DNS requests for asking cs341dangerous.com, relay all other packets correctly
#
# Task 5: Implementing simple HTTP censorship
#   - Let switches send HTTP packets to Controller
#       - By default, switches will send unhandled packets to controller
#   - Additionally, drop HTTP requests for heading cs341dangerous.com, relay all other packets correctlys


###
# If you want, you can define global variables, import libraries, or do others
class Node:
    def __init__(self, name, ip, is_host):
        self.name = name
        self.ip = ip
        self.is_host = is_host
        self.port = dict()  # {1: [Node(...), Node(...)], ...}
        # self.neighbors = dict()


INF = 2**31
# {'h1': (Node(name, IP, true), 0), 's1': (Node(name, None, false), 1), ...}
nodes = dict()
links = []  # 2D-array for dijkstra
###


def init(net) -> None:
    #
    # net argument has following structure:
    #
    # net = {
    #    'hosts': {
    #         'h1': {
    #             'name': 'h1',
    #             'IP': '10.0.0.1',
    #             'links': [
    #                 # (node1, port1, node2, port2, link cost)
    #                 ('h1', 1, 's1', 2, 3)
    #             ],
    #         },
    #         ...
    #     },
    #     'switches': {
    #         's1': {
    #             'name': 's1',
    #             'links': [
    #                 # (node1, port1, node2, port2, link cost)
    #                 ('s1', 2, 'h1', 1, 3)
    #             ]
    #         },
    #         ...
    #     }
    # }
    #
    ###
    global nodes, links

    idx = 0
    hosts = list(net['hosts'].values())
    switches = list(net['switches'].values())

    size = len(hosts) + len(switches)
    links = [[INF]*size for _ in range(size)]  # n by n 2D-array, n = size
    raw_links = []

    for host in hosts:
        nodes[host['name']] = (Node(host['name'], host['IP'], True), idx)
        raw_links.extend(host['links'])
        idx += 1

    for switch in switches:
        nodes[switch['name']] = (Node(switch['name'], None, False), idx)
        raw_links.extend(switch['links'])
        idx += 1

    for (n1, p1, n2, p2, c) in raw_links:
        # print("nodes[n1] is type of", type(nodes[n1]))
        # print("nodes[n1].port is type of", type(nodes[n1].port))
        if not nodes[n1][0].port.get(p1):
            nodes[n1][0].port[p1] = []
        nodes[n1][0].port[p1].append(nodes[n2][0])
        if not nodes[n2][0].port.get(p2):
            nodes[n2][0].port[p2] = []
        nodes[n2][0].port[p2].append(nodes[n1][0])

        n1_idx = nodes[n1][1]
        n2_idx = nodes[n2][1]
        links[n1_idx][n2_idx] = c
    ###


def addrule(switchname: str, connection) -> None:
    #
    # This function is invoked when a new switch is connected to controller
    # Install table entry to the switch's routing table
    #
    # For more information about POX openflow API,
    # Refer to [POX official document](https://noxrepo.github.io/pox-doc/html/),
    # Especially [ofp_flow_mod - Flow table modification](https://noxrepo.github.io/pox-doc/html/#ofp-flow-mod-flow-table-modification)
    # and [Match Structure](https://noxrepo.github.io/pox-doc/html/#match-structure)
    #
    # your code will be look like:
    # msg = ....
    # connection.send(msg)
    ###
    # YOUR CODE HERE
    msg = of.ofp_flow_mod()
    msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    connection.send(msg)

    def dijkstra():
        pass
    ###


def handlePacket(switchname, event, connection):
    packet = event.parsed
    if not packet.parsed:
        print('Ignoring incomplete packet')
        return
    # Retrieve how packet is parsed
    # Packet consists of:
    #  - various protocol headers
    #  - one content
    # For example, a DNS over UDP packet consists of following:
    # [Ethernet Header][           Ethernet Body            ]
    #                  [IPv4 Header][       IPv4 Body       ]
    #                               [UDP Header][ UDP Body  ]
    #                                           [DNS Content]
    # POX will parse the packet as following:
    #   ethernet --> ipv4 --> udp --> dns
    # If POX does not know how to parse content, the content will remain as `bytes`
    #     Currently, HTTP messages are not parsed, remaining `bytes`. you should parse it manually.
    # You can find all available packet header and content types from pox/pox/lib/packet/
    packetfrags = {}
    p = packet
    while p is not None:
        packetfrags[p.__class__.__name__] = p
        if isinstance(p, bytes):
            break
        p = p.next
    print(packet.dump())  # print out unhandled packets
    # How to know protocol header types? see name of class

    # If you want to send packet back to switch, you can use of.ofp_packet_out() message.
    # Refer to [ofp_packet_out - Sending packets from the switch](https://noxrepo.github.io/pox-doc/html/#ofp-packet-out-sending-packets-from-the-switch)
    # You may learn from [l2_learning.py](pox/pox/forwarding/l2_learning.py), which implements learning switches
