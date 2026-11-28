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
package ghidra.ghidrassist;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Convenience wrapper around {@link DecompInterface} for the one-shot
 * "decompile this function to a string" case used by the actions and the
 * export feature. Not reused across calls because the interface holds a
 * native subprocess; each call creates and tears one down.
 */
public final class DecompilerHelper {

	private DecompilerHelper() {
	}

	/** Decompiles a single function to C source. Returns null on failure. */
	public static String decompile(Program program, Function fn, TaskMonitor monitor) {
		if (program == null || fn == null) {
			return null;
		}
		DecompInterface ifc = new DecompInterface();
		try {
			DecompileOptions options = new DecompileOptions();
			ifc.setOptions(options);
			ifc.toggleCCode(true);
			ifc.toggleSyntaxTree(true);
			if (!ifc.openProgram(program)) {
				return null;
			}
			DecompileResults res = ifc.decompileFunction(fn, 60, monitor);
			if (res == null || !res.decompileCompleted()) {
				return null;
			}
			DecompiledFunction df = res.getDecompiledFunction();
			return df == null ? null : df.getC();
		}
		finally {
			ifc.dispose();
		}
	}
}
