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
// Push updated information about function names and other metadata from the current program to a BSim database 
//@category BSim

import java.net.URL;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.protocol.QueryUpdate;
import ghidra.features.bsim.query.protocol.ResponseUpdate;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;

public class UpdateBSimMetadata extends GhidraScript {

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			return;
		}
		String bsim_url = System.getProperty("ghidra.bsimurl");
		if (bsim_url==null || bsim_url.length()==0) {
			bsim_url = askString("Request Repository", "Select URL of database receiving update");
		}

		URL url = BSimClientFactory.deriveBSimURL(bsim_url);
		try (FunctionDatabase database = BSimClientFactory.buildClient(url, true)) {
			if (!database.initialize()) {
				println(database.getLastError().message);
				return;
			}
			println("Connected to " + database.getInfo().databasename);

			GenSignatures gensig = new GenSignatures(false);
			gensig.setVectorFactory(database.getLSHVectorFactory());
			gensig.openProgram(currentProgram, null, null, null, null, null);

			FunctionManager functionManager = currentProgram.getFunctionManager();
			FunctionIterator funciter;
			if (currentSelection != null) {
				println("Scanning selected functions");
				funciter = functionManager.getFunctions(currentSelection, true);
			}
			else {
				println("Scanning all functions");
				funciter = functionManager.getFunctions(true); // If no highlight, update all functions
			}
			gensig.scanFunctionsMetadata(funciter, monitor);
			QueryUpdate update = new QueryUpdate();
			update.manage = gensig.getDescriptionManager();

			ResponseUpdate respup = update.execute(database);		// Try to push the update
			if (respup == null) {
				println(database.getLastError().message);
				return;
			}
			if (!respup.badexe.isEmpty()) {
				for (int j = 0; j < respup.badexe.size(); ++j) {
					ExecutableRecord erec = respup.badexe.get(j);
					println("Database does not contain executable: " + erec.getNameExec());
				}
			}
			if (!respup.badfunc.isEmpty()) {
				int max = respup.badfunc.size();
				if (max > 10) {
					println(
						"Could not find " + Integer.toString(respup.badfunc.size()) + " functions");
					max = 10;
				}
				for (int j = 0; j < max; ++j) {
					FunctionDescription func = respup.badfunc.get(j);
					println("Could not update function " + func.getFunctionName());
				}
			}
			if (respup.exeupdate > 0) {
				println("Updated executable metadata");
			}
			if (respup.funcupdate > 0) {
				println("Updated " + Integer.toString(respup.funcupdate) + " functions");
			}
			if (respup.exeupdate == 0 && respup.funcupdate == 0) {
				println("No changes");
			}
		}
	}

}
