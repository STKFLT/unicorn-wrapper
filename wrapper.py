import unicorn
import itertools
import functools
import IPython

# @formatter:off
arch_mode_matrix = [('arm', unicorn.UC_ARCH_ARM,     (('arm', unicorn.UC_MODE_ARM),
                                                      ('thumb', unicorn.UC_MODE_THUMB),
                                                      ('little_endian', unicorn.UC_MODE_LITTLE_ENDIAN),
                                                      ('mclass', unicorn.UC_MODE_MCLASS),
                                                      ('big_endian', unicorn.UC_MODE_BIG_ENDIAN))),
                    ('arm64', unicorn.UC_ARCH_ARM64, (('arm', unicorn.UC_MODE_ARM),
                                                      ('thumb', unicorn.UC_MODE_THUMB),
                                                      ('little_endian', unicorn.UC_MODE_LITTLE_ENDIAN),
                                                      ('mclass', unicorn.UC_MODE_MCLASS),
                                                      ('big_endian', unicorn.UC_MODE_BIG_ENDIAN))),
                    ('mips', unicorn.UC_ARCH_MIPS,   (('mips32', unicorn.UC_MODE_MIPS32),
                                                      ('mips64', unicorn.UC_MODE_MIPS64),
                                                      ('little_endian', unicorn.UC_MODE_LITTLE_ENDIAN),
                                                      ('big_endian', unicorn.UC_MODE_BIG_ENDIAN))),
                    ('x86', unicorn.UC_ARCH_X86,     (('16', unicorn.UC_MODE_16),
                                                      ('32', unicorn.UC_MODE_32),
                                                      ('64', unicorn.UC_MODE_64),
                                                      ('little_endian', unicorn.UC_MODE_LITTLE_ENDIAN))),

                    ('ppc', unicorn.UC_ARCH_PPC,     (('64', unicorn.UC_MODE_PPC64),
                                                      ('big_endian', unicorn.UC_MODE_BIG_ENDIAN))),
                    ('sparc', unicorn.UC_ARCH_SPARC, (('32', unicorn.UC_MODE_SPARC32),
                                                      ('64', unicorn.UC_MODE_SPARC64),
                                                      ('big_endian', unicorn.UC_MODE_BIG_ENDIAN))),
                    ('m68k', unicorn.UC_ARCH_M68K,   (('big_endian', unicorn.UC_MODE_BIG_ENDIAN),))]
#@formatter:on


class UCFactory(object):
    def __init__(self):
        def init_gen(arch, mode):
            def init(self):
                unicorn.Uc.__init__(self, arch, mode)
        for arch in arch_mode_matrix:
            for mode in arch[2]:
                name = '{}_{}'.format(arch[0], mode[0])
                init_func = functools.partialmethod(UCWrapper.__init__, arch[1], mode[1], arch[0])
                setattr(self, name, type(name+"_mu", (UCWrapper,), {'__init__': init_func}))


class UCWrapper(unicorn.Uc):
    def __init__(self, arch, mode, archname):
        super().__init__(arch, mode)
        arches = list(self.get_arches(archname))
        self.arch = arches[0][1]
        setattr(self, 'reg', getattr(self.arch, archname).reg)
        self.mem = Memory(self)

    def __getitem__(self, key):
        return self.mem[key]

    def __setitem__(self, key, value):
        self.mem[key] = value

    def get_arches(self, archname):
        attrs = dir(unicorn)
        for attr in [x for x in attrs if x == '{}_const'.format(archname)]:
            const = getattr(unicorn, attr)
            consts = dir(const)
            sep_list = [x.split("_") for x in consts if x.startswith("UC_")]
            tree = Tree.tree_from_str_list(sep_list)
            uc_node = tree.nodes[0]

            def un_func(tree_list):
                datas = [x.data for x in tree_list]
                str = "_".join(datas)
                val = getattr(const, str)
                if "_REG_" in str:
                    return Register(self, val)
                elif "_INS_" in str:
                    return Instruction(self, val)

            new_cls = uc_node.attrify(leaf_action=un_func)
            yield (attr.split("_", 1)[0], new_cls)

    def tree_from_str_list(self, list, data=None):
        unique = set([x[0] for x in list if x])
        if len(unique) == 0:
            return Tree(data=data)
        sets = [(y, [x[1:] for x in list if x and x[0] == y]) for y in unique]
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

class Instruction(object):
    def __init__(self, mu, value):
        self.mu = mu
        self.value = value
    #
    # def __get__(self, instance, owner):
    #     return self.value
    #
    # def __set__(self, instance, value):
    #     #TODO: make custom exception
    #     raise ValueError("Cannot set the value of an instruction")

class Memory(object):
    def __init__(self, mu):
        self.mu = mu
        self.ref_dict = {}

    def __getitem__(self, key):
        if isinstance(key, slice):
            if key.step:
                raise IndexError("Memory object does not support stepping")
            if key.start < 0 or key.stop < 0:
                raise IndexError("Memory object does not support negative indexing")
            return self.mu.mem_read(key.start, key.stop - key.start)
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
            else:
                return
        name = "_".join(['UC_Node'] + [y.data.lower() for y in parent_list])
        cls = type(name, (object,), {})
        for x in self.nodes:
            setattr(cls,  x.data.lower(), x.attrify(parent_list + [self], leaf_action))
        return cls()

    @staticmethod
    def tree_from_str_list(list, data=None):
        unique = set([x[0] for x in list if x])
        if len(unique) == 0:
            return Tree(data=data)
        sets = [(y, [x[1:] for x in list if x and x[0] == y]) for y in unique]
        nodes = [Tree.tree_from_str_list(x[1], x[0]) for x in sets]
        return Tree(nodes, data)


factory = UCFactory()

if __name__ == "__main__":
    x = UCFactory()
    mu = x.arm64_arm()
    # code to be emulated
    ARM64_CODE = b"\xab\x05\x00\xb8\xaf\x05\x40\x38"  # str x11, [x13]; ldrb x15, [x13]
    # memory address where emulation starts
    ADDRESS = 0x10000

    mu[ADDRESS] = 2 * 1024 * 1024
    mu[ADDRESS] = ARM64_CODE
    mu['code'] = (ADDRESS, len(ARM64_CODE))
    mu.reg.x11 = 0x12345678
    print(mu.reg.x11)
