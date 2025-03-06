import socket
import struct
import pickle
import os
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import *
from crc import Crc


ARRAY_SIZE = 10
crc32_polinomials = [0x04C11DB7, 0xEDB88320, 0xDB710641, 0x82608EDB, 0x741B8CD7, 0xEB31D82E,
                     0xD663B05, 0xBA0DC66B, 0x32583499, 0x992C1A4C, 0x32583499, 0x992C1A4C]


class CMSController(object):

    def __init__(self, sw_name, set_hash, debug):

        self.topo = load_topo('topology.json')
        self.sw_name = sw_name
        self.set_hash = set_hash
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchThriftAPI(self.thrift_port)

        self.custom_calcs = self.controller.get_custom_crc_calcs()
        self.register_num = len(self.custom_calcs)

        if not debug:
            self.init()
        else:
            self.debug()
        self.registers = []

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
        register_name = "suspicious_ip_pair"

        suspicious_ips = []
        for idx in range(ARRAY_SIZE):
            ip_pair = self.controller.register_read(register_name, idx)
            if ip_pair != 0:  # Ignore empty slots
                src_ip = (ip_pair >> 32) & 0xFFFFFFFF
                dst_ip = ip_pair & 0xFFFFFFFF
                suspicious_ips.append((src_ip, dst_ip))

        print("Suspicious IP pairs:")
        for src, dst in suspicious_ips:
            print(
                f"Source: {self.format_ip(src)}, Destination: {self.format_ip(dst)}")

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

    def debug(self):
        self.get_free_index()
        self.read_suspicious_ips()
        self.read_registers()
        print(self.registers)
        # self.view_suspicious_ip_table()


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
                        type=int, required=False, default=4096)
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
