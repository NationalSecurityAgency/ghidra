define info proc mappings
  python
remote_pid = gdb.execute("getpid-linux-i386", to_string=True).strip()
gdb.execute("remote-proc-mappings {}".format(remote_pid))
  end
end
