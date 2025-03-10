import socket
import struct
import pickle
import os
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import *
from utils import *
from time import sleep


ARRAY_SIZE = 23
THRESHOLD = 30 // 再小拦不住
crc32_polinomials = [0x04C11DB7, 0xEDB88320, 0xDB710641, 0x82608EDB, 0x741B8CD7, 0xEB31D82E,
                     0xD663B05, 0xBA0DC66B, 0x32583499, 0x992C1A4C, 0x32583499, 0x992C1A4C]


class BlackTable():
    def __init__(self) -> None:
        self.table = Heap()

    def insert(self, flow, cnt):
        node = self.table.find_by_metadata(flow)
        if node:
            self.table.update_val(flow, cnt)
        else:
            self.table.insert(cnt, flow)

    @output_with_manager
    def tok_k(self, k):
        max_k_nodes = self.table.get_max_k(k)
        for node in max_k_nodes:
            print(f"Val: {node.val}, Metadata: {node.metadata}")
        return max_k_nodes

    def size(self):
        return self.table.total


class CMSController(object):

    def __init__(self, sw_name, set_hash, debug):

        self.topo = load_topo('topology.json')
        self.sw_name = sw_name
        self.set_hash = set_hash
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchThriftAPI(self.thrift_port)

        self.custom_calcs = self.controller.get_custom_crc_calcs()
        self.register_num = len(self.custom_calcs)

        self.init()
        self.registers = []
        self.black_table = BlackTable()
        if debug:
            self.debug()

    def init(self):
        if self.set_hash:
            self.set_crc_custom_hashes()
            self.init_table()
        self.create_hashes()

    def init_table(self):
        self.init_free_idx()

        table_name = "suspicious_ip_table"
        action_name = "store_suspicious_ip"

        for i in range(ARRAY_SIZE):  # Assuming ARRAY_SIZE = 10
            next_index = (i + 1) % ARRAY_SIZE
            self.controller.table_add(table_name, action_name, [
                                      "1", str(i)], [str(next_index)])

    def init_free_idx(self):
        """Initialize the free_idx register to 0"""
        register_name = "free_idx"
        self.controller.register_write(
            register_name, 0, 0)  # Set free_idx[0] = 0
        print(f"Initialized {register_name} to 0")

    def get_free_index(self):
        """Read the current free index from the register"""
        register_name = "free_idx"
        free_idx = self.controller.register_read(register_name, 0)
        print(f"Current free index: {free_idx}")
        return free_idx

    def set_forwarding(self):
        self.controller.table_add(
            "forwarding", "set_egress_port", ['1'], ['2'])
        self.controller.table_add(
            "forwarding", "set_egress_port", ['2'], ['1'])

    def reset_registers(self):
        for i in range(self.register_num):
            self.controller.register_reset("sketch{}".format(i))

    def flow_to_bytestream(self, flow):
        return socket.inet_aton(flow[0]) + socket.inet_aton(flow[1]) + struct.pack(">HHB", flow[2], flow[3], 6)

    def set_crc_custom_hashes(self):
        i = 0
        for custom_crc32, width in sorted(self.custom_calcs.items()):
            self.controller.set_crc32_parameters(
                custom_crc32, crc32_polinomials[i], 0xffffffff, 0xffffffff, True, True)
            i += 1

    def create_hashes(self):
        self.hashes = []
        for i in range(self.register_num):
            self.hashes.append(
                Crc(32, crc32_polinomials[i], True, 0xffffffff, True, 0xffffffff))

    def read_registers(self):
        self.registers = []
        for i in range(self.register_num):
            self.registers.append(
                self.controller.register_read("sketch{}".format(i)))

    def get_cms(self, flow, mod):
        values = []
        for i in range(self.register_num):
            index = self.hashes[i].bit_by_bit_fast(
                self.flow_to_bytestream(flow)) % mod
            values.append(self.registers[i][index])
        return min(values)

    def decode_registers(self, eps, n, mod, ground_truth_file="sent_flows.pickle"):
        """In the decoding function you were free to compute whatever you wanted.
           This solution includes a very basic statistic, with the number of flows inside the confidence bound.
        """
        self.read_registers()
        confidence_count = 0
        flows = pickle.load(open(ground_truth_file, "rb"))
        for flow, n_packets in flows.items():
            cms = self.get_cms(flow, mod)
            print("Packets sent and read by the cms: {}/{}".format(n_packets, cms))
            if not (cms < (n_packets + (eps*n))):
                confidence_count += 1

        print("Not hold for {}%".format(float(confidence_count)/len(flows)*100))

    def read_suspicious_ips(self):
        """Read all stored suspicious IP pairs from the P4 register."""
        register1 = "suspicious_ip_pair"
        register2 = "suspicious_ip_port_protocol"

        suspicious_ips = []

        for idx in range(ARRAY_SIZE):
            ip_pair = self.controller.register_read(register1, idx)
            ip_port_protocol = self.controller.register_read(register2, idx)
            if ip_pair != 0:  # Ignore empty slots
                src_ip = (ip_pair >> 32) & 0xFFFFFFFF
                dst_ip = ip_pair & 0xFFFFFFFF
                src_port = (ip_port_protocol >> 24) & 0xFFFF
                dst_port = (ip_port_protocol >> 8) & 0xFFFF
                protocol = ip_port_protocol & 0xFF
                suspicious_ips.append(
                    (src_ip, dst_ip, src_port, dst_port, protocol))

        # print("Suspicious Flow Entries:")
        # for src, dst, sport, dport, proto in suspicious_ips:
        #     print(f"Source: {self.format_ip(src)}, Destination: {self.format_ip(dst)}, "
        #           f"SrcPort: {sport}, DstPort: {dport}, Protocol: {proto}")

        return suspicious_ips

    @staticmethod
    def format_ip(ip):
        """Convert a 32-bit integer to a human-readable IP address."""
        return ".".join(map(str, [(ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF]))

    def view_suspicious_ip_table(self):
        """Dump and display the suspicious_ip_table entries."""
        table_name = "MyIngress.suspicious_ip_table"

        entries = self.controller.table_dump(table_name)

        if not entries:
            print("No entries in suspicious_ip_table.")
            return []

        print(f"Entries in {table_name}:")
        for entry in entries:
            print(entry)

        return entries

    def load_suspicious_ips(self):
        ips = self.read_suspicious_ips()
        flow_set = set(ips)
        # for src_ip, dst_ip, src_port, dst_port, proto in flow_set:
        #     flow = (self.format_ip(src_ip), self.format_ip(
        #         dst_ip), src_port, dst_port)
        #     cnt = self.get_cms(flow, 28)
        #     print(
        #         f'src: {self.format_ip(src_ip)}, dst: {self.format_ip(dst_ip)}, cnt: {cnt}')
        return flow_set

    @output_with_manager
    def update_discard_table(self):
        print("update_discard_table")
        top_flows = self.black_table.tok_k(10)  # Retrieve top 10 flows
        for node in top_flows:
            if node.val > THRESHOLD:
                flow_key = node.metadata  # Assuming this contains tuple (srcIP, dstIP, srcPort, dstPort, protocol)
                self.controller.table_add('discard_table', 'drop',
                                          [str(flow_key[0]), str(flow_key[1]),
                                           str(flow_key[2]), str(flow_key[3]),
                                           str(flow_key[4])], [])
                print(f"Flow {flow_key} added to discard table due to high count {node.val}")
            else:
                break

    def remove_from_discard_table(self):
        entries = self.controller.table_dump('discard_table')
        if entries != None:
            for entry in entries:
                flow_key = (entry['key'][0], entry['key'][1], entry['key'][2], entry['key'][3], entry['key'][4])
                node = self.black_table.find_by_metadata(flow_key)
                if not node or node.val <= THRESHOLD:
                    self.controller.table_delete('discard_table',
                                                [str(flow_key[0]), str(flow_key[1]),
                                                str(flow_key[2]), str(flow_key[3]),
                                                str(flow_key[4])])
                    print(f"Flow {flow_key} removed from discard table")

    def debug(self):
        # self.get_free_index()
        # self.read_suspicious_ips()
        # self.read_registers()  # 读取到p4的寄存器计数后才能get_cms
        # self.load_suspicious_ips()
        # print(self.registers)
        # self.view_suspicious_ip_table()

        # TODO 下发流表
        while self.black_table.size() < 30:
            self.read_registers()
            flow_set = set(self.read_suspicious_ips())
            for src_ip, dst_ip, src_port, dst_port, proto in flow_set:
                flow = (self.format_ip(src_ip), self.format_ip(
                    dst_ip), src_port, dst_port, proto)
                cnt = self.get_cms(flow, 28)
                self.black_table.insert(flow, cnt)
                # print(f"size: {self.black_table.size()}")
            self.update_discard_table()
            # self.remove_from_discard_table()
            
        flows = pickle.load(open("sent_flows.pickle", "rb"))
        for flow, n_packets in flows.items():
            if n_packets > 10:
                print(f'{flow}: {n_packets}')
                cms = self.get_cms(flow, 28) # TODO cms有很多个0,p4程序可能有问题
                print("Packets sent and read by the cms: {}/{}".format(n_packets, cms))


if __name__ == "__main__":

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--sw', help="switch name to configure",
                        type=str, required=False, default="s1")
    parser.add_argument('--eps', help="epsilon to use when checking bound",
                        type=float, required=False, default=0.01)
    parser.add_argument('--n', help="number of packets sent by the send.py app",
                        type=int, required=False, default=1000)
    parser.add_argument('--mod', help="number of cells in each register",
                        type=int, required=False, default=28)
    parser.add_argument('--flow-file', help="name of the file generated by send.py",
                        type=str, required=False, default="sent_flows.pickle")
    parser.add_argument('--option', help="controller option can be either set_hashes, decode or reset registers",
                        type=str, required=False, default="set_hashes")
    args = parser.parse_args()

    set_hashes = args.option == "set_hashes"
    debug = args.option == "debug"
    controller = CMSController(args.sw, set_hashes, debug)

    if args.option == "decode":
        controller.decode_registers(args.eps, args.n, args.mod, args.flow_file)

    elif args.option == "reset":
        controller.reset_registers()
