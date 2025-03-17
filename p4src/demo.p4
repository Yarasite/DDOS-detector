#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

#define SKETCH_BUCKET_LENGTH 28
#define SKETCH_CELL_BIT_WIDTH 64
#define ARRAY_SIZE 23
#define THRESHOLD 10

// 每个寄存器有 28 个单元，每个单元的宽度为 64 位
#define SKETCH_REGISTER(num) register<bit<SKETCH_CELL_BIT_WIDTH>>(SKETCH_BUCKET_LENGTH) sketch##num

#define SKETCH_COUNT(num, algorithm) hash(meta.index_sketch##num, HashAlgorithm.algorithm, (bit<16>)0, {hdr.ipv4.srcAddr, \
 hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol}, (bit<32>)SKETCH_BUCKET_LENGTH);\
 sketch##num.read(meta.value_sketch##num, meta.index_sketch##num); \
 meta.value_sketch##num = meta.value_sketch##num +1; \
 sketch##num.write(meta.index_sketch##num, meta.value_sketch##num)

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    // 寄存器定义语句，是在控制块（control）的编译和初始化阶段完成的，而不是在数据包处理阶段
    SKETCH_REGISTER(0); 
    SKETCH_REGISTER(1);
    SKETCH_REGISTER(2);

    // 定义存储可疑 IP 对的数组
	register<bit<64>>(ARRAY_SIZE) suspicious_ip_pair;
    register<bit<64>>(ARRAY_SIZE) suspicious_ip_port_protocol;
    register<bit<32>>(1) free_idx;
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action sketch_count(){
        // 访问 sketch0 寄存器中对应索引的单元，并将该单元的值加 1
        SKETCH_COUNT(0, crc32_custom);
        SKETCH_COUNT(1, crc32_custom);
        SKETCH_COUNT(2, crc32_custom);
    }

    action check() {
        bit<64> min_value;
        bit<32> current_free_idx;

        // 初始化最小值为第一个 sketch 的值
        min_value = meta.value_sketch0;

        // 比较三个 sketch 的值，找出最小值
        if (meta.value_sketch1 < min_value) {
            min_value = meta.value_sketch1;
        }
        if (meta.value_sketch2 < min_value) {
            min_value = meta.value_sketch2;
        }

        if (min_value > THRESHOLD) {
            meta.exceed_threshold = 1;
        } else {
            meta.exceed_threshold = 1;
        }
    }

    action store_suspicious_ip() {
        bit<64> ip_pair = (bit<64>) hdr.ipv4.srcAddr << 32 | (bit<64>) hdr.ipv4.dstAddr;
        bit<64> ip_port_protocol = ((bit<64>) hdr.tcp.srcPort << 24) |
                                    ((bit<64>) hdr.tcp.dstPort << 8) |
                                    ((bit<64>) hdr.ipv4.protocol);  

        // Read current index and store suspicious I
        suspicious_ip_pair.write(meta.current_free_idx, ip_pair);
        suspicious_ip_port_protocol.write(meta.current_free_idx, ip_port_protocol);

        // Use lookup table for next index update
        if(meta.current_free_idx + 1 >= ARRAY_SIZE) {
            meta.next_free_idx = 0;
        } else {
            meta.next_free_idx = meta.current_free_idx + 1;
        }
        free_idx.write(0, meta.next_free_idx);
    }

    action set_egress_port(bit<9> egress_port){
        standard_metadata.egress_spec = egress_port;
    }

    table forwarding {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_egress_port;
            drop;
            NoAction;
        }
        size = 64;
        default_action = drop;
    }

    table discard_table {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.srcPort:  exact;
            hdr.tcp.dstPort:  exact;
            hdr.ipv4.protocol: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table suspicious_ip_table {
        key = {
            meta.exceed_threshold: exact;  // Only apply when threshold exceeded
        }
        actions = {
            store_suspicious_ip;
            NoAction;
        }
        size = ARRAY_SIZE;
        default_action = NoAction;
    }

    apply {
        discard_table.apply();
        //apply sketch
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()){
            sketch_count();
            check();  // Determine if threshold is exceeded
            
            // Read current free index before applying table
            free_idx.read(meta.current_free_idx, 0);
            
            suspicious_ip_table.apply();  // Store IP only if exceed_threshold is true
        }

        forwarding.apply();
    }
}

control MyEgress(inout headers hdr,
        inout metadata meta,
        inout standard_metadata_t standard_metadata) {
    apply {}
}

control MyComputeChecksum(inout headers hdr,
        inout metadata meta) {
    apply {}
}



V1Switch(
    MyParser(), 
    MyVerifyChecksum(), 
    MyIngress(), 
    MyEgress(), 
    MyComputeChecksum(), 
    MyDeparser()
) main;
