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
package ghidra.app.plugin.core.decompiler.export;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.parallel.DecompileConfigurer;

public class ExportDecompilerConfigurer implements DecompileConfigurer {

	final ExportDecompInterface ifc = new ExportDecompInterface();

	@Override
	public void configure(DecompInterface decompiler) {
		decompiler.setOptions(new DecompileOptions());
		// can also use "normalize" but that won't generate HighVariables
		decompiler.setSimplificationStyle("decompile");
	}

	ExportDecompInterface getInterface() {
		return ifc;
	}

}
