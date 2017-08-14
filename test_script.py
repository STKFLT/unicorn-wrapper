from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division
from __future__ import absolute_import
from future import standard_library
standard_library.install_aliases()
import wrapper

mu = wrapper.factory.arm64_arm()
# code to be emulated
ARM64_CODE = b"\xab\x05\x00\xb8\xaf\x05\x40\x38"  # str x11, [x13]; ldrb x15, [x13]
# memory address where emulation starts
ADDRESS = 0x10000

mu[ADDRESS] = 2 * 1024 * 1024
mu[ADDRESS] = ARM64_CODE
mu['code'] = (ADDRESS, len(ARM64_CODE))
mu.reg.x11 = 0x12345678
mu.reg.x13 = 0x10008
mu.reg.x15 = 0x33
mu.emu_start(ADDRESS, ADDRESS+len(ARM64_CODE))
print(">>> X15 0x{:x}".format(mu.reg.x15))
