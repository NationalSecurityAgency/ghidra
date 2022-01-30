# Memory map blocks CSV import
#
#@category Import.MemoryMap
#@author Ruslan Isaev
#keybinding
#@menupath File.Import.Memory map CSV
#@toolbar

from docking.widgets.filechooser import GhidraFileChooser
from docking.widgets.filechooser import GhidraFileChooserMode
from ghidra.util.filechooser import ExtensionFileFilter
from java.io import File
from os.path import expanduser

import csv
 
def csv_read(str, is_str = False):
  import csv
  if is_str:
    r = csv.reader(str.splitlines())  
  else:
    r = csv.reader(open(str))
  return list(r)

def mem_add(mem, name, off, size, overlay = False, \
 is_readable = True, is_writable = True, \
 is_executable = False, is_volatile = False, comment = ""):
  off_ = toAddr(off)
  mem.createUninitializedBlock(name, off_, int(size, 16), overlay)
  blk = mem.getBlock(off_)
  blk.setPermissions(is_readable, is_writable, is_executable)
  blk.setComment(comment)
  blk.setVolatile(is_volatile)


def mem_del(mem, name, is_offset = False):
  if is_offset:
    blk = mem.getBlock(toAddr(name))
  else:
    blk = mem.getBlock(name)
  mem.removeBlock(blk, monitor)

def lst_flip(lst):
  return dict(zip(lst, range(len(lst))))

def import_ghidra_mmap(csv):
  mem = currentProgram.getMemory()
  cols = lst_flip(csv[0])
  for row in csv[1:]:
    kwargs = {}
    kwargs["mem"] = mem
    kwargs["name"]= row[cols["Name"]]
    kwargs["off"] = row[cols["Start"]]
    kwargs["size"] = row[cols["Length"]]
    if "Overlay" in cols.keys() and row[cols["Overlay"]]:
      kwargs["overlay"] = True
    if "R" in cols.keys() and row[cols["R"]]:
      kwargs["is_readable"] = True
    if "W" in cols.keys() and row[cols["W"]]:
      kwargs["is_writable"] = True
    if "X" in cols.keys() and row[cols["X"]]:
      kwargs["is_executable"] = True
    if "Volatile" in cols.keys() and row[cols["Volatile"]]:
      kwargs["is_volatile"] = True
    if "Comment" in cols.keys():
      kwargs["comment"] = row[cols["Comment"]]
    try:
      mem_add(**kwargs)  
    except:
      print("Unable to add memory block", row)

def get_mmap_csv_path():
  fileChooser = GhidraFileChooser(None);
  fileChooser.addFileFilter(ExtensionFileFilter.forExtensions("Ghidra memory map csv", "csv"));
  homeDirectory = File(expanduser("~"));
  fileChooser.setCurrentDirectory(homeDirectory);
  fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
  fileChooser.setApproveButtonToolTipText("Choose csv file to import memory map");
  fileChooser.setTitle("Select file that contains csv file in Ghidra memory map csv export format");
  file = fileChooser.getSelectedFile();
  if file is None:
    sys.exit(1)
  else:
    return file.getPath()   

csv_file_path = get_mmap_csv_path()
csv = csv_read(csv_file_path)
import_ghidra_mmap(csv)
