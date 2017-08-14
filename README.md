#Unicorn-wrapper

A wrapper that uses Python's language features to streamline the interface to Unicorn Engine. Not even close to functional yet.

Currently only some register and memory actions are supported. As time goes on more features will be converted with the goal of avoiding the use of constants and keeping things as Pythonic™ as possible.

##Examples
```python
# mapping a memory segment:
# Unicorn
mu.mem_map(ADDRESS, 2 * 1024 * 1024)
#unicorn_wrapper
mu[ADDRESS] = 2*1024*1024

#writing to memory:
#Unicorn
mu.mem_write(ADDRESS, ARM64_CODE)
#unicorn_wrapper
mu[ADDRESS] = ARM64_CODE

#reading memory:
#Unicorn
mu.mem_read(ADDRESS, len(ARM64_CODE))
#unicorn_wrapper
mu[ADDRESS:ADDRESS+len(ARM64_CODE)]

#reading a register:
#Unicorn
mu.reg_read(UC_ARM64_REG_X11)
#unicorn_wrapper
mu.reg.x11

#writing a register:
#Unicorn
mu.reg_write(UC_ARM64_REG_X11, 0x12345678)
#unicorn_wrapper
mu.reg.x11 = 0x12345678
```