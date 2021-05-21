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
//Example preScript to configure the PDB symbol server service to use the ~/symbols directory
//as the location to store symbol files, and to search Microsoft's public
//symbol server.
//The ~/symbols directory should already exist and be initialized as a symbol
//storage location.
//@category PDB
import java.util.List;

import java.io.File;
import java.net.URI;

import ghidra.app.plugin.core.analysis.PdbAnalyzer;
import ghidra.app.plugin.core.analysis.PdbUniversalAnalyzer;
import ghidra.app.script.GhidraScript;
import pdb.PdbPlugin;
import pdb.symbolserver.*;

public class PdbSymbolServerExamplePrescript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		File homeDir = new File(System.getProperty("user.home"));
		File symDir = new File(homeDir, "symbols");
		LocalSymbolStore localSymbolStore = new LocalSymbolStore(symDir);
		HttpSymbolServer msSymbolServer =
			new HttpSymbolServer(URI.create("https://msdl.microsoft.com/download/symbols/"));
		SymbolServerService symbolServerService =
			new SymbolServerService(localSymbolStore, List.of(msSymbolServer));

		PdbPlugin.saveSymbolServerServiceConfig(symbolServerService);

		// You only need to enable the "allow remote" option on the specific
		// analyzer you are using
		PdbUniversalAnalyzer.setAllowRemoteOption(currentProgram, true);
		PdbAnalyzer.setAllowRemoteOption(currentProgram, true);
	}
}

