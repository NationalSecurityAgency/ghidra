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
// Generate the BSim signature for the function currently 
// containing the cursor and dump the feature hashes to the console.
//@category BSim

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.signature.SignatureResult;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class DumpBSimSignaturesScript extends GhidraScript {

	protected static final int SIGNATURE_SETTINGS = 0x4d;

	@Override
	public void run() throws Exception {
		if (isRunningHeadless()) {
			popup("This script must be run in the Ghidra GUI");
			return;
		}
		if (currentProgram == null) {
			popup("This script requires an open program");
			return;
		}
		Function func = getFunctionContaining(currentAddress);
		if (func == null) {
			popup("No function selected!");
			return;
		}

		DecompInterface decompiler = new DecompInterface();
		try {
			decompiler.setOptions(new DecompileOptions());
			decompiler.toggleSyntaxTree(false);
			decompiler.setSignatureSettings(SIGNATURE_SETTINGS);
			if (!decompiler.openProgram(currentProgram)) {
				println("Unable to initalize the Decompiler interface");
				println(decompiler.getLastMessage());
				return;
			}

			StringBuffer buf = new StringBuffer();
			buf.append("\nFunction: ");
			buf.append(func.getName());
			buf.append("\nentry: ");
			buf.append(func.getEntryPoint().toString());
			buf.append("\n\n");
			getSignatures(buf, decompiler, func);
			printf("%s\n", buf.toString());
		}
		finally {
			decompiler.closeProgram();
			decompiler.dispose();
		}
	}

	protected void getSignatures(StringBuffer buf, DecompInterface decompiler, Function func) {
		SignatureResult sigres = decompiler.generateSignatures(func, false, 10, null);
		for (int feature : sigres.features) {
			buf.append(Integer.toHexString(feature));
			buf.append("\n");
		}
	}

}
