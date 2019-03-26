/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.decompiler.flatapi;

import ghidra.app.decompiler.*;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Function;
import ghidra.util.Disposable;

public class FlatDecompilerAPI implements Disposable {
	protected FlatProgramAPI flatProgramAPI;
	protected DecompInterface decompiler;

	/**
	 * Initializes without a provided FlatProgramAPI instance...this must be set before
	 * using the FlatDecompilerAPI!
	 */
	public FlatDecompilerAPI() {
		// nothing to do...
	}

	/**
	 * Initializes with a provided FlatProgramAPI instance.
	 * @param flatProgramAPI the FlatProgramAPI instance.
	 */
	public FlatDecompilerAPI(FlatProgramAPI flatProgramAPI) {
		this.flatProgramAPI = flatProgramAPI;
	}

	/**
	 * Gets the actual decompiler (may be null if not initialized).
	 * @return the decompiler
	 */
	public DecompInterface getDecompiler() {
		return decompiler;
	}

	/**
	 * Decompiles the specified function and returns a
	 * string containing the decompilation.
	 * This call does not impose a timeout.
	 * @param function the function to decompile
	 * @return a string containing the decompilation
	 */
	public final String decompile(Function function) throws Exception {
		return decompile(function, 0);
	}

	/**
	 * Decompiles the specified function and returns a
	 * string containing the decompilation.
	 * @param function the function to decompile
	 * @param timeoutSecs maximum time allowed for decompile to complete.
	 * @return a string containing the decompilation
	 */
	public final String decompile(Function function, int timeoutSecs) throws Exception {
		initialize();
		DecompileResults decompRes =
			decompiler.decompileFunction(function, timeoutSecs, flatProgramAPI.getMonitor());

		DecompiledFunction res = decompRes.getDecompiledFunction();
		if (res == null)
			throw new DecompileException("Decompiler", decompRes.getErrorMessage());
		return res.getC();
	}

	/**
	 * Initializes the decompiler instance.
	 */
	public final void initialize() throws Exception {
		if (decompiler == null) {
			decompiler = new DecompInterface();
			decompiler.openProgram(flatProgramAPI.getCurrentProgram());
		}
	}

	/**
	 * Disposes of the decompiler resources by calling currentDecompiler.dispose().
	 */
	public void dispose() {
		if (decompiler != null) {
			decompiler.dispose();
		}
	}
}
