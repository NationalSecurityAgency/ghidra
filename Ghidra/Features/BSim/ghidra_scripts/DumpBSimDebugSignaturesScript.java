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
// Generate the BSim signature for the function currently containing the cursor 
// and dump the feature hashes and debug information to the console.
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.signature.DebugSignature;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;

public class DumpBSimDebugSignaturesScript extends DumpBSimSignaturesScript {

	@Override
	protected void getSignatures(StringBuffer buf, DecompInterface decompiler, Function func) {
		List<DebugSignature> sigres = decompiler.debugSignatures(func, 10, null);
		Language language = currentProgram.getLanguage();
		for (int i = 0; i < sigres.size(); ++i) {
			sigres.get(i).printRaw(language, buf);
			buf.append("\n");
		}
	}

}
