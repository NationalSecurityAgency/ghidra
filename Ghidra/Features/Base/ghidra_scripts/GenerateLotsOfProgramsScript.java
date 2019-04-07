/* ###
 * IP: GHIDRA
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
import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;

public class GenerateLotsOfProgramsScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		DomainFolder root = getProjectRootFolder();
		DomainFolder stuff = root.createFolder("stuff");
		createPrograms(stuff, 30);
		DomainFolder a = stuff.createFolder("A");
		createPrograms(a, 10);
		DomainFolder b = stuff.createFolder("B");
		createPrograms(b, 10);
		DomainFolder c = stuff.createFolder("C");
		createPrograms(c, 10);
		DomainFolder d = stuff.createFolder("D");
		createPrograms(d, 10);
		DomainFolder e = stuff.createFolder("E");
		createPrograms(e, 10);
		DomainFolder f = stuff.createFolder("F");
		createPrograms(f, 10);

		DomainFolder big = a.createFolder("Big");
		createPrograms(big, 200);
	}

	private void createPrograms(DomainFolder parent, int count)
			throws IOException, InvalidNameException, CancelledException {
		Processor processor = Processor.toProcessor("x86");
		Language language = getDefaultLanguage(processor);
		Program program = new ProgramDB("dummy", language, language.getDefaultCompilerSpec(), this);
		for (int i = 0; i < count; i++) {
			parent.createFile("Prog_" + i, program, monitor);
		}
		program.release(this);
	}

}
