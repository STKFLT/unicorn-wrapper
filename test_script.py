from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division
from __future__ import absolute_import
from future import standard_library
standard_library.install_aliases()
from wrapper import Factory, Hook
import IPython



# code to be emulated
ARM64_CODE = b"\xab\x05\x00\xb8\xaf\x05\x40\x38"  # str x11, [x13]; ldrb x15, [x13]
# memory address where emulation starts
ADDRESS = 0x10000


@Hook.hook_block
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))

@Hook.hook_code(ADDRESS, ADDRESS+len(ARM64_CODE))
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))


mu = Factory.arm64_arm()
mu[ADDRESS] = 2 * 1024 * 1024
mu[ADDRESS] = ARM64_CODE
mu['code'] = (ADDRESS, len(ARM64_CODE))
mu.reg.x11 = 0x12345678
mu.reg.x13 = 0x10008
mu.reg.x15 = 0x33
mu.emu_start(ADDRESS, ADDRESS+len(ARM64_CODE))
print(">>> X15 0x{:x}".format(mu.reg.x15))
IPython.embed()
