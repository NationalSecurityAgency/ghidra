# A GDB command to obtain the PID of a traced process, which must be running
# on an x86 Linux host. This is primarily useful when running gdbserver.exe
# under Wine.
#
# Note that binaries linked with non-executable stacks, such as those
# created by the `-z,noexecstack` or `/NXCOMPAT` options, should replace
# `($esp-7)` with an address that will be mapped to an executable region.
# Selection of such an address is platform- and binary-specific.

define getpid-linux-i386
  # MOV eax,20 [SYS_getpid]
  # INT 0x80
  # RET
  set $linux_getpid = {int (void)}($esp-7)
  set {unsigned char[8]}($linux_getpid) = {\
    0xB8, 0x14, 0x00, 0x00, 0x00, \
    0xCD, 0x80, \
    0xC3 \
  }
  output $linux_getpid()
  echo \n
end
