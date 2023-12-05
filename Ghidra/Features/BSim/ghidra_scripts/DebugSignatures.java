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

import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.signature.DebugSignature;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;

public class DebugSignatures extends GhidraScript {

	private static final int SIGNATURE_SETTINGS = 0x45;

	@Override
	protected void run() throws Exception {
		Function func = this.getFunctionContaining(this.currentAddress);

		if (func == null) {
			popup("No function selected!");
			return;
		}

		DecompInterface decompiler = new DecompInterface();
		decompiler.setOptions(new DecompileOptions());
		decompiler.toggleSyntaxTree(false);
		decompiler.setSignatureSettings(SIGNATURE_SETTINGS);
		if (!decompiler.openProgram(this.currentProgram)) {
			println("Unable to initalize the Decompiler interface");
			println(decompiler.getLastMessage());
			return;
		}

		Language language = this.currentProgram.getLanguage();
		List<DebugSignature> sigres = decompiler.debugSignatures(func, 10, null);

		StringBuffer buf = new StringBuffer();
		buf.append("\nFunction: ");
		buf.append(func.getName());
		buf.append("\nentry: ");
		buf.append(func.getEntryPoint().toString());
		buf.append("\n\n");
		if (sigres == null) {
			printf("Null sigres!\n");
		}
		else {
			for (int i = 0; i < sigres.size(); ++i) {
				sigres.get(i).printRaw(language, buf);
				buf.append("\n");
			}
		}
		printf("%s\n", buf.toString());
		decompiler.closeProgram();
		decompiler.dispose();
	}

}
