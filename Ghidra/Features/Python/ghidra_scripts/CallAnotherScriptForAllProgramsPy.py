# Shows how to run a script on all of the programs within the current project.

# DISCLAIMER: This is a recreation of a Java Ghidra script for example
# use only. Please run the Java version in a production environment.

# NOTE: Script will only process unversioned and checked-out files.

#@category Examples.Python

from ghidra.app.script import GhidraState
from ghidra.framework.model import *
from ghidra.program.database import ProgramContentHandler
from ghidra.program.model.listing import Program
from ghidra.util.exception import CancelledException
from ghidra.util.exception import VersionException

from java.io import IOException

# The script referenced in the following line should be replaced with the script to be called
SUBSCRIPT_NAME = "AddCommentToProgramScript.java"

def recurseProjectFolder(domainFolder):
    files = domainFolder.getFiles()
    for domainFile in files:
        processDomainFile(domainFile)
    folders = domainFolder.getFolders()
    for folder in folders:
        recurseProjectFolder(folder)
         
def processDomainFile(domainFile):
    if not ProgramContentHandler.PROGRAM_CONTENT_TYPE == domainFile.getContentType():
        return  # skip non-Program files
    if domainFile.isVersioned() and not domainFile.isCheckedOut():
        println("WARNING! Skipping versioned file - not checked-out: " + domainFile.getPathname())
    program = None
    consumer = java.lang.Object() 
    try:
        program = domainFile.getDomainObject(consumer, True, False, monitor)
        processProgram(program)
           
    except VersionException:
        println("ERROR! Failed to process file due to upgrade issue: " + domainFile.getPathname())
        
    finally:
        if program is not None:
            program.release(consumer)
             
def processProgram(program):
    """Do you program work here """
    println("Processing: " + program.getDomainFile().getPathname())
    monitor.setMessage("Processing: " + program.getDomainFile().getName())
    id = program.startTransaction("Batch Script Transaction")
    try:
        newState = GhidraState(state.getTool(), state.getProject(), program, None, None, None)
        runScript(SUBSCRIPT_NAME, newState)
         
    except Exception:
        printerr("ERROR! Exception occurred while processing file: " + program.getDomainFile().getPathname())
        printerr("       " + Exception.getMessage())
        e.printStackTrace()
     
    finally:
        program.endTransaction(id, True)

    # ...save any changes
    program.save("Changes made by script: " + SUBSCRIPT_NAME, monitor)

if currentProgram is not None:
    popup("This script should be run from a tool with no open programs")
    exit()
     
project = state.getProject()
projectData = project.getProjectData()
rootFolder = projectData.getRootFolder()
recurseProjectFolder(rootFolder)
