from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division
from __future__ import absolute_import
from builtins import super
from future import standard_library

standard_library.install_aliases()
import unicorn
import itertools
import functools


# partialmethod for python2.7 support
# https://gist.github.com/carymrobbins/8940382
class partialmethod(functools.partial):
    def __get__(self, instance, owner):
        if instance is None:
            return self
        return functools.partial(self.func, instance, *(self.args or ()), **(self.keywords or {}))

def optional_arg_decorator(fn):
    def wrapped_decorator(*args):
        if len(args) == 1 and callable(args[0]):
            return fn(args[0])

        else:
            def real_decorator(decoratee):
                return fn(decoratee, *args)

            return real_decorator

    return wrapped_decorator
# @formatter:off
arch_mode_matrix = [('arm', unicorn.UC_ARCH_ARM,     (('arm',           unicorn.UC_MODE_ARM),
                                                      ('thumb',         unicorn.UC_MODE_THUMB),
                                                      ('little_endian', unicorn.UC_MODE_LITTLE_ENDIAN),
                                                      ('mclass',        unicorn.UC_MODE_MCLASS),
                                                      ('big_endian',    unicorn.UC_MODE_BIG_ENDIAN))),
                    ('arm64', unicorn.UC_ARCH_ARM64, (('arm',           unicorn.UC_MODE_ARM),
                                                      ('thumb',         unicorn.UC_MODE_THUMB),
                                                      ('little_endian', unicorn.UC_MODE_LITTLE_ENDIAN),
                                                      ('mclass',        unicorn.UC_MODE_MCLASS),
                                                      ('big_endian',    unicorn.UC_MODE_BIG_ENDIAN))),
                    ('mips', unicorn.UC_ARCH_MIPS,   (('mips32',        unicorn.UC_MODE_MIPS32),
                                                      ('mips64',        unicorn.UC_MODE_MIPS64),
                                                      ('little_endian', unicorn.UC_MODE_LITTLE_ENDIAN),
                                                      ('big_endian',    unicorn.UC_MODE_BIG_ENDIAN))),
                    ('x86', unicorn.UC_ARCH_X86,     (('16',            unicorn.UC_MODE_16),
                                                      ('32',            unicorn.UC_MODE_32),
                                                      ('64',            unicorn.UC_MODE_64),
                                                      ('little_endian', unicorn.UC_MODE_LITTLE_ENDIAN))),
                    ('ppc', unicorn.UC_ARCH_PPC,     (('64',            unicorn.UC_MODE_PPC64),
                                                      ('big_endian',    unicorn.UC_MODE_BIG_ENDIAN))),
                    ('sparc', unicorn.UC_ARCH_SPARC, (('32',            unicorn.UC_MODE_SPARC32),
                                                      ('64',            unicorn.UC_MODE_SPARC64),
                                                      ('big_endian',    unicorn.UC_MODE_BIG_ENDIAN))),
                    ('m68k', unicorn.UC_ARCH_M68K,   (('big_endian',    unicorn.UC_MODE_BIG_ENDIAN),))]
# @formatter:on


class UCFactory(object):
    def __init__(self):
        self.hooks_list = []
        def func(tree_list):
            datas = [x.data for x in tree_list]
            string = "_".join(datas)
            val = getattr(unicorn, string)
            attr_name = "hook_{}".format(tree_list[-1].data.lower())
            return (attr_name, HookDecorator(self.hooks_list, val))
        self.hooks = self.get_hooks(func).attrify(leaf_action=func, class_base='UC_Node')[1]
        for arch in arch_mode_matrix:
            for mode in arch[2]:
                name = '{}_{}'.format(arch[0], mode[0])
                init_func = partialmethod(UCWrapper.__init__, arch[1], mode[1], arch[0], self.hooks_list)
                setattr(self, name, type(str(name + "_mu"), (UCWrapper,), {'__init__': init_func}))


    @staticmethod
    def get_hooks(func=None):
        attrs = dir(unicorn)
        sep_list = [x.split("_") for x in attrs if x.startswith("UC_")]
        # fix split hooks
        sep_list = [x[:2]+["_".join(x[2:])] if "HOOK" in x else x for x in sep_list]
        tree = Tree.tree_from_str_list(sep_list)
        uc_node = tree.nodes[0]
        uc_node.nodes = [x for x in uc_node.nodes if x.data=="HOOK"]
        return uc_node

class UCWrapper(unicorn.Uc):
    def __init__(self, arch, mode, arch_name, hook_list=None):
        super().__init__(arch, mode)
        self.arch = self.get_arch(arch_name)
        self.hook = self.build_hooks()
        for hook in hook_list:
            self.hook_add(*hook[0], **hook[1])
#        for attr in dir(self.constants.hook)]:
#            setattr(self.hook, 'add_{}_hook'.format(attr), getattr(self.constants.hook, attr))
        self.reg = getattr(self.arch, arch_name).reg
        self.mem = Memory(self)

    def __getitem__(self, key):
        return self.mem[key]

    def __setitem__(self, key, value):
        self.mem[key] = value

    def get_arch(self, arch_name):
        attr = getattr(unicorn, '{}_const'.format(arch_name), None)
        if not attr:
            raise ValueError("{} is not a valid arch".format(arch_name))
        consts = dir(attr)
        sep_list = [x.split("_") for x in consts if x.startswith("UC_")]
        tree = Tree.tree_from_str_list(sep_list)
        uc_node = tree.nodes[0]

        def un_func(tree_list):
            datas = [x.data for x in tree_list]
            string = "_".join(datas)
            val = getattr(attr, string)
            attr_name = tree_list[-1].data.lower()
            if "_REG_" in string:
                return (attr_name, Register(self, val))
            elif "_INS_" in string:
                return (attr_name, Instruction(self, val))

        return uc_node.attrify(leaf_action=un_func, class_base='UC_Node')[1]
    def build_hooks(self):
        def func(tree_list):
            datas = [x.data for x in tree_list]
            string = "_".join(datas)
            val = getattr(unicorn, string)
            attr_name = "hook_{}".format(tree_list[-1].data.lower())
            return (attr_name, HookType(self, val))
        uc_node = UCFactory.get_hooks(func)
        return uc_node.attrify(leaf_action=func, class_base='UC_Node')[1].hook

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

    def __get__(self, instance, owner):
        return self.value

    def __set__(self, instance, value):
        # TODO: make custom exception
        raise ValueError("Cannot set the value of an instruction")


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
            return self.mu.mem_read(key, 1)
        elif isinstance(key, str):
            range_ = self.ref_dict.get(key, None)
            if range_:
                return self[range_[0]:range_[1]]
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

class HookType(object):
    def __init__(self, mu, value):
        self.mu = mu
        self.value = value
    def __call__(self, *args, **kwargs):

        self.mu.hook_add(self.value, *args, **kwargs)


def args(args):
    pass

class HookDecorator(object):
    def __init__(self, hook_list, value):
        self.hook_list = hook_list
        self.value = value
    def __call__(self, *args, **kwargs):
        if len(args) == 1 and callable(args[0]):
            self._hookify(args[0])
            return args[0]
        def wrap(f):
            return self._hookify(f, *args, **kwargs)
        return wrap

    def _hookify(self, func, *args, **kwargs):
        args2 = tuple([self.value, func] + list(args))
        self.hook_list.append((args2, kwargs))
        return func

class Tree(object):
    def __init__(self, nodes=None, data=None):
        if nodes:
            self.nodes = nodes
        else:
            self.nodes = []
        self.data = data

    def attrify(self, parent_list=None, leaf_action=None, class_base='Class_Gen'):
        if parent_list is None:
            parent_list = []
        if not self.nodes:
            if leaf_action:
                return leaf_action(parent_list + [self])
            else:
                return
        name = "_".join([class_base] + [y.data.lower() for y in parent_list])
        cls = type(str(name), (object,), {})
        for x in self.nodes:
            res = x.attrify(parent_list + [self], leaf_action, class_base)
            setattr(cls, res[0], res[1])
        return (self.data.lower(), cls())

    def __str__(self):
        return 'Tree(data={}) with {} node(s)'.format(self.data, len(self.nodes))

    @staticmethod
    def tree_from_str_list(str_list, data=None):
        unique = set([x[0] for x in str_list if x])
        if len(unique) == 0:
            return Tree(data=data)
        sets = [(y, [x[1:] for x in str_list if x and x[0] == y]) for y in unique]
        nodes = [Tree.tree_from_str_list(x[1], x[0]) for x in sets]
        return Tree(nodes, data)


Factory = UCFactory()
Hook = Factory.hooks.hook