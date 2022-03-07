## ###
#  IP: GHIDRA
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#       http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##
# This Ghidra script runs YARA on the file associated with the current program in the Ghidra Code Browser.
# The user supplies a YARA rule file.  Upon a match, the YARA rule name is reported in the comment at
# the memory address corresponding to the YARA-provided file offset.
# If 'yara' (Linux/OS X) or 'yara64.exe' (Windows) is not on $PATH, then the user is prompted to locate the YARA executable.
# A dropdown box asks the user to locate the binary that YARA will scan.  The two possible conditions are:
# 1. This Ghidra script runs YARA on the file at the same location as when it was imported
# or a on the file that the user has since moved to a new location.
# 2. The user has imported the file into Ghidra and the user has since deleted the file.  This Ghidra script attempts to
# generate the original bytes of the imported file and asks the user to provide a filename to store the bytes.  YARA then runs on that file.

#@category Memory.YARA

import os.path
import sys
import distutils.spawn
from subprocess import Popen, PIPE
from ghidra.framework import Platform, OperatingSystem
from org.apache.commons.io import FileUtils
from ghidra.program.database.mem import FileBytes
import jarray
from docking.widgets.filechooser import GhidraFileChooser
from docking.widgets.filechooser import GhidraFileChooserMode
from ghidra.util.filechooser import ExtensionFileFilter
from java.io import File
from os.path import expanduser

def getYaraRulePath():
  fileChooser = GhidraFileChooser(None);
  fileChooser.addFileFilter(ExtensionFileFilter.forExtensions("YARA files", "yara"));
  fileChooser.addFileFilter(ExtensionFileFilter.forExtensions("YARA files", "yar")); 
  fileChooser.setCurrentDirectory(None);
  homeDirectory = File(expanduser("~"));
  fileChooser.setCurrentDirectory(homeDirectory);
  fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
  fileChooser.setApproveButtonToolTipText("Choose file for YARA scan.");
  fileChooser.setTitle("Select File That Contains Your YARA Rules");
  file = fileChooser.getSelectedFile();
  if file is None:
    sys.exit(1)
  else:
    return file.getPath()     

#Use Ghidra's Executable Location to identify the executable file that corresponds
#to the program in the Code Browser if the file does not exist, then prompt
#the user to locate the binary.
def getYaraTargetOnDisk():
  yaraTargetPath = currentProgram.getDomainFile().getMetadata()['Executable Location']
  if(Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS):
    yaraTargetPath = yaraTargetPath.replace('/','\\').lstrip("\\")
  if(not os.path.exists(yaraTargetPath)):
    yaraTargetPath = askFile(getScriptName() + ': The binary associated with the'\
                     ' current program cannot be found.  Select the executable '\
                     'file that YARA will analyze.', 'Select executable file').getPath()
  if yaraTargetPath is None:
    sys.exit(1)
  return yaraTargetPath

#if the user has deleted the executable file at Executable Location, then
#save the original bytes of the imported file to disk
#split file into 4096-sized chunks then write to file (in case file is large)
def getYaraTargetFromGhidra():
  yaraTargetPath = askFile('Choose a file where Ghidra Program bytes will be saved.', 'Choose file:')
  if yaraTargetPath is None:
    sys.exit(1)
  if os.path.exists(yaraTargetPath.getPath()):
    os.remove(yaraTargetPath.getPath())

  CHUNK_SIZE = 4096
  buf = jarray.zeros(CHUNK_SIZE,"b")
  fBytes = currentProgram.getMemory().getAllFileBytes().get(0)
  sizeFBytes = fBytes.getSize()

  for k in range(0, sizeFBytes+1, CHUNK_SIZE):
    count = fBytes.getOriginalBytes(k,buf,0,CHUNK_SIZE)
    if count == 0:
      break
    buf2 = buf[0:count]
    FileUtils.writeByteArrayToFile(yaraTargetPath, buf2, True)
  return yaraTargetPath.getPath()
  
#Each key in the YARA dictionary is a YARA rule name.
#The values associated with each key are the YARA file offsets
#where each file offset represents a match for that rule
def createYaraDictionary(stdout):
  lines = stdout.splitlines()
  if lines == None:
    println('No YARA matches detected.')
    sys.exit(1)
  yaraDictionary = {}
  for line in lines:
  #we have the rule name and executable file path
    if not line.startswith('0x'): 
      ruleName = line.split(' ')[0]
      yaraDictionary[ruleName] = []
    #we have the file offset where the YARA rule matches in the file
    else: 
      yaraDictionary[ruleName].append(line.split(':')[0])
  return yaraDictionary

#Run YARA on the file (on disk) associated with the program in the Ghidra Code Browser
#Output from YARA will be recorded via the stdout for the YARA proccess
def launchYaraProcess(yaraRulePath, yaraTargetPath):
  #find the location of the YARA executable on the user's machine
  if(Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS):
    #since Ghidra requires 64-bit, the user probably has yara64
    yaraExecutablePath = distutils.spawn.find_executable("yara64.exe")
  else:
    yaraExecutablePath = distutils.spawn.find_executable("yara")
  #if we cannot find YARA, then ask the user where YARA is located
  if(yaraExecutablePath is None):
    yaraExecutablePath = askFile(getScriptName() + \
                        ': Select the YARA executable file',\
                        'Select YARA executable').getPath()
    if yaraExecutablePath is None:
      sys.exit(1)
  try:
    yaraProcess = Popen([yaraExecutablePath,yaraRulePath,'-sw',yaraTargetPath],stdout=PIPE,stderr=PIPE,bufsize=-1)
    stdout,stderr = yaraProcess.communicate()
  except:
    println('Failed to launch YARA. Is YARA on your $PATH?')
    sys.exit(1)
  if yaraProcess.returncode != 0:
    println('The YARA process failed with return code of %d.  Is there a mistake in your rule file?' % yaraProcess.returncode)
    println('The YARA process error: %s.' % str(stderr))
    sys.exit(1)
  yaraDictionary = createYaraDictionary(stdout)
  yaraProcess.stdout.close()
  yaraProcess.stderr.close()
  return yaraDictionary
  
#Start each comment that has at least one YARA match with 'YARA'
#so users can easily filter through comments in the Ghidra Comments window
def setGhidraComment(memoryAddress,fileOffset,yaraRuleName):
  myCodeUnit = currentProgram.getListing().getCodeUnitContaining(memoryAddress)
  existingComment = myCodeUnit.getComment(0)
  #A pre-existing comment does  not exist so add this YARA signature to the comment and we are done
  if not existingComment:
    # 0 for end-of-line comment
    myCodeUnit.setComment(0, 'YARA: \n'+yaraRuleName)
    return
  #A comment already exists at this code unit so append our new comment to that comment
  #Assume that we have already run this script on this file and
  #the comments that already exist are separated by \n
  else:
    #store the pre-existing comments in commentList
    commentList = []
    comments = existingComment.split('\n')
    for comment in comments:
      #remove 'YARA' from the \n-separated comments
      if 'YARA' not in comment:
        commentList.append(comment)
    newComment = ''
    #if this YARA rule name is not already reported for this CodeUnit, then add it to commentList
    if yaraRuleName not in commentList:
      commentList.append(yaraRuleName)
      lengthCommentList = len(commentList)
      if lengthCommentList==1:
        newComment = commentList[0]
      else:
        #Create the comment such that each yara rule name is separated by \n
        for k in range(lengthCommentList-1):
          newComment = newComment+commentList[k]+'\n'
        #append to the last comment in the list
        newComment = newComment+commentList[-1]
      myCodeUnit.setComment(0,'YARA: \n'+newComment)
    #the comment already contains the YARA rule name so do nothing
    else:
      println('INFO: This YARA rule is already reported for this CodeUnit. '
              'Rule name: %s. Memory address: %s. File offset: %s.' %
              (yaraRuleName,memoryAddress.toString(), hex(fileOffset)))
      return

def main():
  choiceList = []
  choiceList.append('Binary exists on disk.')
  choiceList.append('Ghidra will create a new instance of the imported bytes and save them to a file.')
  choice = askChoice('Select the file that YARA will scan.', 'Please choose one', choiceList, choiceList[0])

  #the program probably still exists at the same location as when the file was imported into Ghidra
  if choice == choiceList[0]:
    yaraTargetPath = getYaraTargetOnDisk()
  #if the binary is not located on disk, extract bytes from Ghidra and save to disk.  Scan with YARA.
  else:
    yaraTargetPath = getYaraTargetFromGhidra()

  yaraRulePath = getYaraRulePath()
  yaraDictionary = launchYaraProcess(yaraRulePath, yaraTargetPath)

  if bool(yaraDictionary):
    mem = currentProgram.getMemory()
    for key in yaraDictionary:
      for fileOffset in yaraDictionary[key]:
        myFileOffset = long(fileOffset,16)
        addressList = mem.locateAddressesForFileOffset(myFileOffset)
        if addressList.isEmpty():
          println('No memory address found for: ' + hex(myFileOffset))
        elif addressList.size() == 1:
          address = addressList.get(0)
          setGhidraComment(address,myFileOffset,key)
        #file offset matches to multiple addresses.  Let the user decide which address they want.
        else:
          println('WARN: The file offset ' + hex(myFileOffset) + ' matches to the following memory addresses:')
          addressChoiceList = []
          for addr in addressList:
            println('\t ' + mem.getBlock(addr).getName() + ':' + addr.toString())
            addressChoiceList.append(mem.getBlock(addr).getName() + ':' + addr.toString())
          addressChoice = askChoice('Select the memory address that corresponds to the file offset: ' + hex(myFileOffset), 'Please choose one', addressChoiceList, addressChoiceList[0])
          selectedAddress = addressChoice.split(':')
          addrSelected = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(selectedAddress[-1])
          setGhidraComment(addrSelected,myFileOffset,key)  
  else:
    println('No YARA matches.')
              
if __name__ == "__main__":
  main()
