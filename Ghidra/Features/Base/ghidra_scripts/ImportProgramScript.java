/* ###
 * IP: GHIDRA
 * REVIEWED: YES
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Imports a program and opens it in the current tool.
//@category Import

import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;

import java.io.File;


public class ImportProgramScript extends GhidraScript {

    /**
     * @see ghidra.app.script.GhidraScript#run()
     */
    @Override
    public void run() throws Exception {
        File file = askFile("Please specify a file to import", "Import");

        Program program = importFile(file);
        if (program == null) {
            Language language = getDefaultLanguage(Processor.findOrPossiblyCreateProcessor("x86"));
            if (language == null) {
                println("Unable to locate default language for "+Processor.findOrPossiblyCreateProcessor("x86"));
                return;
            }
            CompilerSpec compilerSpec = language.getDefaultCompilerSpec();
            program = importFileAsBinary(file, language, compilerSpec);
        }
        if (program == null) {
            println("Unable to import program from file "+file.getName());
            return;
        }
        openProgram(program);
    }

}
