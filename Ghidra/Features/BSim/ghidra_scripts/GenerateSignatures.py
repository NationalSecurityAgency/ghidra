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
#Generate signatures for every function in the current program and write them to an XML file in a user-specified directory
#@category BSim.python

import java.lang.System as System
import java.io.File as File
import ghidra.features.bsim.query.FunctionDatabase as FunctionDatabase
import ghidra.features.bsim.query.GenSignatures as GenSignatures
import java.io.FileWriter as FileWriter

def run():
    md5String = currentProgram.getExecutableMD5()
    if (md5String is None) or (len(md5String) < 10):
        raise IOException("Could not get MD5 on file: " + currentProgram.getName())
    basename = "sigs_" + md5String
    System.setProperty("ghidra.output",basename)
    workingDir = askDirectory("GenerateSignatures:", "Working Directory")
    if not workingDir.isDirectory():
        popup("Must select a working directory")
        return
    outfile = File(workingDir,basename)
    vectorFactory = FunctionDatabase.generateLSHVectorFactory()
    gensig = GenSignatures(True)
    templateName = askString("GenerateSignatures:", "Database template", "medium_nosize")
    config = FunctionDatabase.loadConfigurationTemplate(templateName)
    vectorFactory.set(config.weightfactory, config.idflookup, config.info.settings)
    gensig.setVectorFactory(vectorFactory)
    gensig.addExecutableCategories(config.info.execats)
    gensig.addFunctionTags(config.info.functionTags)
    gensig.addDateColumnName(config.info.dateColumnName)
    repo = "ghidra://localhost/" + state.getProject().getName()
    path = GenSignatures.getPathFromDomainFile(currentProgram)
    gensig.openProgram(currentProgram,None,None,None,repo,path)
    fman = currentProgram.getFunctionManager()
    iter = fman.getFunctions(True)
    gensig.scanFunctions(iter, fman.getFunctionCount(), monitor)
    fwrite = FileWriter(outfile)
    manager = gensig.getDescriptionManager()
    manager.saveXml(fwrite)
    fwrite.close()
    return

run()

