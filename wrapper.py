import unicorn
import itertools

class UCWrapper(object):
    def __init__(self, arch='arm64'):
        self.mu = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
        arches = list(self.get_arches())
        self.arch = arches[0][1]
        setattr(self, 'reg', self.arch.arm64.reg)
        self.mem = Memory(self.mu)



    def __getitem__(self, key):
        return self.mem[key]

    def __setitem__(self, key, value):
        self.mem[key] = value

    def get_arches(self):
        attrs = dir(unicorn)
        for attr in [x for x in attrs if x.endswith('arm64_const')]:
            const = getattr(unicorn, attr)
            consts = dir(const)
            sep_list = [x.split("_") for x in consts if x.startswith("UC_")]
            tree = self.tree_from_str_list(sep_list)
            uc_node = tree.nodes[0]
            def un_func(tree_list):
                datas = [x.data for x in tree_list]
                str = "_".join(datas)
                val = getattr(const, str)
                return Register(self.mu, val)
            uc_node.attrify(leaf_action=un_func)
            yield (attr.split("_", 1)[0], uc_node)

    def _reg_read(self, reg):
        return self.mu.reg_read(reg)

    def _reg_write(self, reg, val):
        return self.mu.reg_write(reg, val)


    def tree_from_str_list(self, list, data=None):
        unique = set([x[0] for x in list if x])
        if len(unique) == 0:
            return Tree(data=data)
        sets = [(y,[x[1:] for x in list if x[0]==y]) for y in unique]
        nodes = [self.tree_from_str_list(x[1], x[0]) for x in sets]
        return Tree(nodes, data)


class Register(object):
    def __init__(self, mu, value):
        self.mu = mu
        self.value = value

    def __get__(self, instance, owner):
        return self.mu.reg_read(self.value)

    def __set__(self, instance, value):
        self.mu.reg_write(self.value, value)

class Memory(object):
    def __init__(self, mu):
        self.mu = mu
        self.ref_dict = {}
    def __getitem__(self, key):
        if isinstance(key, slice):
            if key.step:
                raise IndexError("Memory object does not support stepping")
            if key.start<0 or key.stop < 0:
                raise IndexError("Memory object does not support negative indexing")
            return self.mu.mem_read(key.start, key.stop-key.start)
        elif isinstance(key, int):
            return self.mu.mem_read(int, 1)
        elif isinstance(key, str):
            range = self.ref_dict.get(key, None)
            if range:
                return self.mu.mem_read(*range)
            raise KeyError

    def __setitem__(self, key, value):
        if isinstance(key, str):
            if len(value) != 2:
                raise ValueError
            self.ref_dict[key] = value
        elif isinstance(key, int):
            if isinstance(value, int):
                self.mu.mem_map(key, value)
            else:
                self.mu.mem_write(key, value)


class Tree(object):
    def __init__(self, nodes=None, data=None, getter=None, setter=None):
        if nodes:
            self.nodes = nodes
        else:
            self.nodes = []
        self.data = data

    def traverse(self):
        generators = []
        for node in self.nodes:
            generators.append(node.traverse())
        for item in itertools.chain(*generators):
            yield item
        if self.data:
            yield self.data

    def attrify(self, parent_list=None, leaf_action=None):
        if parent_list is None:
            parent_list = []
        if not self.nodes:
            if leaf_action:
                return leaf_action(parent_list + [self])
        for x in self.nodes:
            setattr(self.__class__, x.data.lower(), x.attrify(parent_list+[self], leaf_action))
        return self

if __name__ == "__main__":
    mu = UCWrapper()
    # code to be emulated
    ARM64_CODE = b"\xab\x05\x00\xb8\xaf\x05\x40\x38"  # str x11, [x13]; ldrb x15, [x13]
    # memory address where emulation starts
    ADDRESS = 0x10000

    mu[ADDRESS] = 2 * 1024 * 1024
    mu[ADDRESS] = ARM64_CODE
    mu['code'] = (ADDRESS, len(ARM64_CODE))
    mu.reg.x11 = 0x12345678
    print(mu.reg.x11)