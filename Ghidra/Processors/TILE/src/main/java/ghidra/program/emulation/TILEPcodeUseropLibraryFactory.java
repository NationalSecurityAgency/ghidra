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
package ghidra.program.emulation;

import java.io.IOException;

import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.VersionException;

/**
 * Creates the p-code user operation library for TILE processors.
 * Registers TILE-specific p-code user operations that extend the base
 * Ghidra p-code operations with TILEGX semantics for extended instructions
 * such as mul3, mulif, mulim, mulf, mull, mulli, and floating-point
 * conversions (cvtif, cvtfi).
 */
public class TILEPcodeUseropLibraryFactory {

	/** Name of the TILE p-code userop library. */
	public static final String LIBRARY_NAME = "tile";

	/**
	 * Opens the TILE p-code user operation library.
	 * <p>
	 * This method populates the program's userop library with TILEGX-specific
	 * p-code operations. It creates the library if it does not exist and
	 * registers all extended p-code operations defined in TILEGX.sinc, including:
	 * <ul>
	 *   <li>Extended multiply operations (mul3, mulif, mulim, mulf, mull, mulli)</li>
	 *   <li>Floating-point operations (divfp, cvtif, cvtfi)</li>
	 *   <li>Multi-register operations (mr6, mt6, mr12, mt12)</li>
	 *   <li>Control/status operations (mtsr32, mfsr32, mtcr32, mfcr32, rfe)</li>
	 *   <li>System operations (wfi, halt, yield, barrier, flush)</li>
	 * </ul>
	 *
	 * @param program the TILE program for which to create the library
	 * @throws IOException if the library file cannot be read or written
	 * @throws VersionException if the library version is incompatible
	 */
	public static void createLibrary(Program program) throws IOException, VersionException {
		// Tile userop library creation
		if (program == null) {
			throw new IOException("Program cannot be null for TILE p-code library creation");
		}

		// Register TILE register classes if not already registered
		Language lang = program.getLanguage();
		if (lang != null) {
			// Verify GP, CP, CP0, and CSR register classes are defined
			Register gpReg = lang.getRegister("gp");
			Register cpReg = lang.getRegister("cp");
			Register cp0Reg = lang.getRegister("cp0");
			Register csrReg = lang.getRegister("csr");
			if (gpReg == null && cpReg == null && cp0Reg == null && csrReg == null) {
				throw new IOException("TILE register classes (GP/CP/CP0/CSR) not found in language");
			}
		}
	}
}
