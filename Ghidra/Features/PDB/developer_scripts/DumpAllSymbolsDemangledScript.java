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
// Script for ghizard developer investigating template and ICF squashing.
//
//@category PDB
import java.io.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import mdemangler.*;
import mdemangler.object.MDObjectCPP;

public class DumpAllSymbolsDemangledScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		File dumpFile = askFile("Choose an output file", "OK");
		if (dumpFile == null) {
			Msg.info(this, "Canceled execution due to no output file");
			return;
		}
		if (dumpFile.exists()) {
			if (!askYesNo("Confirm Overwrite", "Overwrite file: " + dumpFile.getName())) {
				Msg.info(this, "Operation canceled");
				return;
			}
		}
		FileWriter fileWriter = new FileWriter(dumpFile);
		BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);

		SymbolTable st = currentProgram.getSymbolTable();
		SymbolIterator it = st.getDefinedSymbols();

		while (it.hasNext() && !monitor.isCancelled()) {
			Symbol s = it.next();
			if (s.getSource() == SourceType.DEFAULT) {
				continue;
			}

			Address addr = s.getAddress();
			if (addr.isExternalAddress() || Address.NO_ADDRESS.equals(addr)) {
				continue;
			}

			String name = s.getName();
			String demangled = getDemangledString(name);
			if (demangled != null && !demangled.isBlank()) {
				name = demangled;
			}

			bufferedWriter.append(addr + " " + name + "\n");
		}
		bufferedWriter.close();
	}

	/**
	 * Gets a demangled string for the indicated mangled string.
	 * @param mangledString the mangled string to be decoded
	 * @return the associated demangled string
	 */
	private static String getDemangledString(String mangledString) {
		MDMangGhidra demangler = new MDMangGhidra();
		try {
			MDParsableItem parsableItem = demangler.demangle(mangledString, true);
			if (parsableItem instanceof MDObjectCPP) {
				MDObjectCPP mdObject = (MDObjectCPP) parsableItem;
				return mdObject.getQualifiedName().toString();
			}
//			if (parsableItem instanceof MDFunctionType) {
//				MDFunctionType functionType = (MDFunctionType) parsableItem;
//				return functionType.getName();
//			}
//			if (parsableItem instanceof MDDataType) {
//				MDDataType dataType = (MDDataType) parsableItem;
//				return dataType.getName();
//			}
			return parsableItem.toString();
		}
		catch (MDException e) {
			// Couldn't demangle.
			Msg.info(null, e.getMessage());
			return null;
		}
	}

}
