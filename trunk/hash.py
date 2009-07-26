import sys

def LoadExports(module_name):
  exports = []
  for export in open(module_name + ".exports.txt"):
    while export[-1] in ['\r', '\n']:
      export = export[:-1]
    exports.append(export)
  return exports

def GetHash(s, xor, start):
  (AL, AH) = (0, start)
  for c in (s+"\0"):
    AL = ord(c)
    AL ^= xor
    AH -= AL
    AH &= 0xFF
  return AH

def ReportHashes(procs, hash, xor, start):
  print '%-39s equ 0x%02X' % ("hash_xor_value", xor)
  print '%-39s equ 0x%02X' % ("hash_start_value", start)
  for proc in procs:
    (module, function) = proc.split(".");
    proc_hash = hash(function, xor, start)
    equ_name = "hash_%s_%s" % (module, function)
    print '%-39s equ 0x%02X' % (equ_name, proc_hash)

def CheckHashes(exports, procs, hash, xor, start, report_failures = False):
  for proc in procs:
    (module, function) = proc.split(".");
    proc_hash = hash(function, xor, start)
    for export in exports[module]:
      export_hash = hash(export, xor, start)
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
    xor = ParseArg(sys.argv[1]);
    start = ParseArg(sys.argv[2]);
    print "--- %02X ---" % xor
    print "* %02X" % start
    if CheckHashes(exports, procs, GetHash, xor, start, True):
      ReportHashes(procs, GetHash, xor, start)
  elif len(sys.argv) == 2:
    # Accept one argument: a decimal or hexadecimal number that is used by the
    # hashing algorithm:
    xor = ParseArg(sys.argv[1]);
    print "--- %02X ---" % xor
    for start in range(0, 0x100):
      if CheckHashes(exports, procs, GetHash, xor, start, True):
        print "* %02X" % start
        ReportHashes(procs, GetHash, xor, start)
  else:
    # If no argument is specified, search for all number that do not give
    # collisions:
    for xor in range(0, 0x100):
      bHeaderShown = False
      print "--- %02X ---\r" % xor,
      for start in range(0, 0x100):
        if CheckHashes(exports, procs, GetHash, xor, start):
          if (not bHeaderShown):
            print "--- %02X ---" % xor
            bHeaderShown = True
          print "%02X " % start,
      if (bHeaderShown):
        print ""


if __name__ == "__main__":
  Main()
