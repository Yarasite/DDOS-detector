import multiprocessing
import builtins

class Crc(object):
    """
    A base class for CRC routines.
    """
    # pylint: disable=too-many-instance-attributes

    def __init__(self, width, poly, reflect_in, xor_in, reflect_out, xor_out, table_idx_width=None, slice_by=1):
        """The Crc constructor.

        The parameters are as follows:
            width
            poly
            reflect_in
            xor_in
            reflect_out
            xor_out
        """
        # pylint: disable=too-many-arguments

        self.width = width
        self.poly = poly
        self.reflect_in = reflect_in
        self.xor_in = xor_in
        self.reflect_out = reflect_out
        self.xor_out = xor_out
        self.tbl_idx_width = table_idx_width
        self.slice_by = slice_by

        self.msb_mask = 0x1 << (self.width - 1)
        self.mask = ((self.msb_mask - 1) << 1) | 1
        if self.tbl_idx_width != None:
            self.tbl_width = 1 << self.tbl_idx_width
        else:
            self.tbl_idx_width = 8
            self.tbl_width = 1 << self.tbl_idx_width

        self.direct_init = self.xor_in
        self.nondirect_init = self.__get_nondirect_init(self.xor_in)
        if self.width < 8:
            self.crc_shift = 8 - self.width
        else:
            self.crc_shift = 0

    def __get_nondirect_init(self, init):
        """
        return the non-direct init if the direct algorithm has been selected.
        """
        crc = init
        for dummy_i in range(self.width):
            bit = crc & 0x01
            if bit:
                crc ^= self.poly
            crc >>= 1
            if bit:
                crc |= self.msb_mask
        return crc & self.mask

    def reflect(self, data, width):
        """
        reflect a data word, i.e. reverts the bit order.
        """
        # pylint: disable=no-self-use

        res = data & 0x01
        for dummy_i in range(width - 1):
            data >>= 1
            res = (res << 1) | (data & 0x01)
        return res

    def bit_by_bit(self, in_data):
        """
        Classic simple and slow CRC implementation.  This function iterates bit
        by bit over the augmented input message and returns the calculated CRC
        value at the end.
        """

        reg = self.nondirect_init
        for octet in in_data:
            if self.reflect_in:
                octet = self.reflect(octet, 8)
            for i in range(8):
                topbit = reg & self.msb_mask
                reg = ((reg << 1) & self.mask) | ((octet >> (7 - i)) & 0x01)
                if topbit:
                    reg ^= self.poly

        for i in range(self.width):
            topbit = reg & self.msb_mask
            reg = ((reg << 1) & self.mask)
            if topbit:
                reg ^= self.poly

        if self.reflect_out:
            reg = self.reflect(reg, self.width)
        return (reg ^ self.xor_out) & self.mask

    def bit_by_bit_fast(self, in_data):
        """
        This is a slightly modified version of the bit-by-bit algorithm: it
        does not need to loop over the augmented bits, i.e. the Width 0-bits
        wich are appended to the input message in the bit-by-bit algorithm.
        """

        reg = self.direct_init
        for octet in in_data:
            if self.reflect_in:
                octet = self.reflect(octet, 8)
            for i in range(8):
                topbit = reg & self.msb_mask
                if octet & (0x80 >> i):
                    topbit ^= self.msb_mask
                reg <<= 1
                if topbit:
                    reg ^= self.poly
            reg &= self.mask
        if self.reflect_out:
            reg = self.reflect(reg, self.width)
        return reg ^ self.xor_out


class HeapNode:
    def __init__(self, val, metadata):
        self.val = val
        self.metadata = metadata

    def __lt__(self, other):
        return self.val < other.val


class Heap:
    def __init__(self):
        self.heap = []
        self.total = 0
        # 用于快速查找，键为 metadata，值为节点在堆中的索引
        self.metadata_index_map = {}

    def _parent(self, index):
        return (index - 1) // 2

    def _left_child(self, index):
        return 2 * index + 1

    def _right_child(self, index):
        return 2 * index + 2

    def _swap(self, i, j):
        # 交换节点位置时，更新 metadata 到索引的映射
        self.metadata_index_map[self.heap[i].metadata] = j
        self.metadata_index_map[self.heap[j].metadata] = i
        self.heap[i], self.heap[j] = self.heap[j], self.heap[i]

    def _sift_up(self, index):
        while index > 0 and self.heap[self._parent(index)] < self.heap[index]:
            self._swap(self._parent(index), index)
            index = self._parent(index)

    def _sift_down(self, index):
        max_index = index
        left = self._left_child(index)
        if left < len(self.heap) and self.heap[left] > self.heap[max_index]:
            max_index = left
        right = self._right_child(index)
        if right < len(self.heap) and self.heap[right] > self.heap[max_index]:
            max_index = right
        if index != max_index:
            self._swap(index, max_index)
            self._sift_down(max_index)

    def insert(self, val, metadata):
        node = HeapNode(val, metadata)
        self.heap.append(node)
        self.total += val
        # 记录新插入节点的 metadata 对应的索引
        self.metadata_index_map[metadata] = len(self.heap) - 1
        self._sift_up(len(self.heap) - 1)

    def delete(self):
        if len(self.heap) == 0:
            return None
        if len(self.heap) == 1:
            self.total = 0
            del self.metadata_index_map[self.heap[0].metadata]
            return self.heap.pop()
        max_node = self.heap[0]
        self.total -= max_node.val
        del self.metadata_index_map[max_node.metadata]
        last_node = self.heap.pop()
        self.heap[0] = last_node
        self.metadata_index_map[last_node.metadata] = 0
        self._sift_down(0)
        return max_node

    def get_max_k(self, k):
        if k > len(self.heap):
            k = len(self.heap)
        temp_heap = self.heap.copy()
        temp_metadata_index_map = self.metadata_index_map.copy()
        result = []
        for _ in range(k):
            max_node = self.delete()
            result.append(max_node)
        self.heap = temp_heap
        self.metadata_index_map = temp_metadata_index_map
        self.total = sum(node.val for node in self.heap)
        return result

    def find_by_metadata(self, metadata):
        # 根据 metadata 在 O(1) 时间内查找节点
        if metadata in self.metadata_index_map:
            index = self.metadata_index_map[metadata]
            return self.heap[index]
        return None

    def update_val(self, metadata, new_val):
        if metadata not in self.metadata_index_map:
            return False
        index = self.metadata_index_map[metadata]
        old_val = self.heap[index].val
        # 更新节点的 val
        self.heap[index].val = new_val
        # 更新 total
        self.total = self.total - old_val + new_val
        if new_val > old_val:
            # 如果新值大于旧值，向上调整堆
            self._sift_up(index)
        elif new_val < old_val:
            # 如果新值小于旧值，向下调整堆
            self._sift_down(index)
        return True


def output_with_manager(func):
    def wrapper(*args, **kwargs):
        output_manager = OutputManager()
        original_print = builtins.print  # 使用 builtins.print
        
        def custom_print(*messages):
            output_manager.send_message(" ".join(map(str, messages)))
        
        try:
            builtins.print = custom_print  # 修改内置的打印函数
            return func(*args, **kwargs)
        finally:
            builtins.print = original_print
    return wrapper

class OutputManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(OutputManager, cls).__new__(cls)
            cls._instance._init_output_process()
        return cls._instance

    def _init_output_process(self):
        # 创建一个队列，用于在主进程和输出进程之间传递信息
        self.message_queue = multiprocessing.Queue()
        # 创建并启动输出进程
        self.output_process = multiprocessing.Process(target=self._output_worker, args=(self.message_queue,))
        self.output_process.start()

    def _output_worker(self, queue):
        # 使用局部变量保存上一次的消息，用于过滤重复消息
        last_message = None
        while True:
            message = queue.get()
            if message is None:
                break
            if message != last_message:
                print(message)
                last_message = message

    def send_message(self, message):
        self.message_queue.put(message)

    def stop(self):
        self.message_queue.put(None)
        self.output_process.join()
        print("Output process terminated.")



@output_with_manager
def test():
    print("test")
    print("test")


if __name__ == "__main__":
    test()
    # 测试代码
    # heap = Heap()
    # heap.insert(3, "meta3")
    # heap.insert(5, "meta5")
    # heap.insert(1, "meta1")
    # heap.insert(7, "meta7")
    # print("Total:", heap.total)
    # max_k_nodes = heap.get_max_k(2)
    # for node in max_k_nodes:
    #     print(f"Val: {node.val}, Metadata: {node.metadata}")
    # deleted_node = heap.delete()
    # if deleted_node:
    #     print(
    #         f"Deleted Val: {deleted_node.val}, Metadata: {deleted_node.metadata}")
    # print("Total after deletion:", heap.total)

    # # 测试查找功能
    # found_node = heap.find_by_metadata("meta5")
    # if found_node:
    #     print(f"Found Val: {found_node.val}, Metadata: {found_node.metadata}")
    # else:
    #     print("Node not found.")

    # # 测试更新功能
    # if heap.update_val("meta5", 8):
    #     print("Updated successfully.")
    #     updated_node = heap.find_by_metadata("meta5")
    #     if updated_node:
    #         print(
    #             f"Updated Val: {updated_node.val}, Metadata: {updated_node.metadata}")
    #         print("New Total:", heap.total)
    # else:
    #     print("Update failed.")
    
