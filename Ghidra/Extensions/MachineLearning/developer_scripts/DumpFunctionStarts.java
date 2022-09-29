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
//Writes a list of the addresses of all function starts and their sizes to a file
//@category machineLearning

import java.io.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DumpFunctionStarts extends GhidraScript {

	private static final String DATA_DIR = "/local/funcstarts/stripped";

	@Override
	protected void run() throws Exception {
		File outFile =
			new File(DATA_DIR + File.separator + currentProgram.getName() + "_stripped_funcs");
		FileWriter fWriter = new FileWriter(outFile);
		BufferedWriter bWriter = new BufferedWriter(fWriter);
		FunctionIterator fIter = currentProgram.getFunctionManager().getFunctions(true);
		while (fIter.hasNext()) {
			Function func = fIter.next();
			if (func.isExternal()) {
				continue;
			}
			long size = func.getBody().getNumAddresses();
			bWriter.write(func.getEntryPoint().toString() + "," + size + "\n");
		}
		bWriter.close();
	}

}
