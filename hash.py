import sys

def LoadExports(module_name):
  exports = []
  for export in open(module_name + ".exports.txt"):
    while export[-1] in ['\r', '\n']:
      export = export[:-1]
    exports.append(export)
  return exports

def GetHash(s, x):
  (AL, AH) = (0, 0)
  for c in (s+"\0"):
    AL = ord(c)
    AL ^= x
    AH -= AL
    AH &= 0xFF
  return AH

def ReportHashes(procs, hash, x):
  for proc in procs:
    proc_hash = hash(proc, x)
    print '"%s" = %02X' % (proc, proc_hash)

def CheckHashes(exports, procs, hash, x, report_failures = False):
  for proc in procs:
    proc_hash = hash(proc, x)
    for export in exports:
      export_hash = hash(export, x)
      if export_hash == proc_hash:
        if export != proc:
          if report_failures:
            print '"%s" collides with "%s"' % (proc, export)
          return False
        else:
          break
    else:
      raise Exception("Function \"%s\" not exported!" % proc)
  return True

def Main():
  kernel32_exports = LoadExports("kernel32")
  ws2_32_exports = LoadExports("ws2_32")
  kernel32_procs = ["CreateProcessA", "LoadLibraryA"]
  ws2_32_procs = ["WSAStartup", "WSASocketA", "bind", "listen", "accept"]
  if len(sys.argv) == 2:
    # Accept one argument: a decimal or hexadecimal number that is used by the
    # hashing algorithm:
    if sys.argv[1][0:2] == "0x":
      x = int(sys.argv[1][2:], 16)
    else:
      x = int(sys.argv[1])
    print "--- %02X ---" % x
    if (CheckHashes(kernel32_exports, kernel32_procs, GetHash, x, True) and
        CheckHashes(ws2_32_exports, ws2_32_procs, GetHash, x, True)):
      ReportHashes(kernel32_procs, GetHash, x)
      ReportHashes(ws2_32_procs, GetHash, x)
  else:
    # If no argument is specified, search for all number that do not give
    # collisions:
    for x in range(0, 0x100):
      if (CheckHashes(kernel32_exports, kernel32_procs, GetHash, x) and
          CheckHashes(ws2_32_exports, ws2_32_procs, GetHash, x)):
        print "--- %02X ---" % x
        ReportHashes(kernel32_procs, GetHash, x)
        ReportHashes(ws2_32_procs, GetHash, x)


if __name__ == "__main__":
  Main()
