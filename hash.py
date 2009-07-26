import sys

def LoadExports(module_name):
  exports = []
  for export in open(module_name + ".exports.txt"):
    while export[-1] in ['\r', '\n']:
      export = export[:-1]
    exports.append(export)
  return exports

def GetHash(s, x, y):
  (AL, AH) = (0, y)
  for c in (s+"\0"):
    AL = ord(c)
    AL ^= x
    AH -= AL
    AH &= 0xFF
  return AH

def ReportHashes(procs, hash, x, y):
  print '%-39s equ 0x%02X' % ("hash_xor_value", x)
  print '%-39s equ 0x%02X' % ("hash_start_value", y)
  for proc in procs:
    (module, function) = proc.split(".");
    proc_hash = hash(function, x, y)
    equ_name = "hash_%s_%s" % (module, function)
    print '%-39s equ 0x%02X' % (equ_name, proc_hash)

def CheckHashes(exports, procs, hash, x, y, report_failures = False):
  for proc in procs:
    (module, function) = proc.split(".");
    proc_hash = hash(function, x, y)
    for export in exports[module]:
      export_hash = hash(export, x, y)
      if export_hash == proc_hash:
        if export != function:
          if report_failures:
            print '"%s" collides with "%s"' % (function, export)
          return False
        else:
          break
    else:
      raise Exception("Function \"%s\" not exported!" % function)
  return True

def ParseArg(s):
  if s[0:2] == "0x":
    return int(s[2:], 16)
  if s[0] == "'":
    return ord(s[1])
  return int(s)

def Main():
  exports = {
      "kernel32": LoadExports("kernel32"),
      "ws2_32": LoadExports("ws2_32")
  }
  procs = ["kernel32.CreateProcessA", "kernel32.LoadLibraryA",
      "ws2_32.WSAStartup", "ws2_32.WSASocketA", "ws2_32.bind", 
      "ws2_32.listen", "ws2_32.accept"]
  if len(sys.argv) == 3:
    x = ParseArg(sys.argv[1]);
    y = ParseArg(sys.argv[2]);
    print "--- %02X ---" % x
    print "* %02X" % y
    if CheckHashes(exports, procs, GetHash, x, y, True):
      ReportHashes(procs, GetHash, x, y)
  elif len(sys.argv) == 2:
    # Accept one argument: a decimal or hexadecimal number that is used by the
    # hashing algorithm:
    x = ParseArg(sys.argv[1]);
    print "--- %02X ---" % x
    for y in range(0, 0x100):
      if CheckHashes(exports, procs, GetHash, x, y, True):
        print "* %02X" % y
        ReportHashes(procs, GetHash, x, y)
  else:
    # If no argument is specified, search for all number that do not give
    # collisions:
    for x in range(0, 0x100):
      bHeaderShown = False
      print "--- %02X ---\r" % x,
      for y in range(0, 0x100):
        if CheckHashes(exports, procs, GetHash, x, y):
          if (not bHeaderShown):
            print "--- %02X ---" % x
            bHeaderShown = True
          print "%02X " % y,
      if (bHeaderShown):
        print ""


if __name__ == "__main__":
  Main()
