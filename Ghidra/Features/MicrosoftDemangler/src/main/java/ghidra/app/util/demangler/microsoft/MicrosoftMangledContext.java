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
package ghidra.app.util.demangler.microsoft;

import ghidra.app.util.demangler.MangledContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * A simple class to contain the context of a mangled symbol for demangling
 */
public class MicrosoftMangledContext extends MangledContext {

	/**
	 * Constructor for mangled context
	 * @param program the program; can be null
	 * @param options the demangler options
	 * @param mangled the mangled string
	 * @param address the address; can be null
	 */
	public MicrosoftMangledContext(Program program, MicrosoftDemanglerOptions options,
			String mangled, Address address) {
		super(program, options, mangled, address);
	}

	/**
	 * Returns the program architecture size
	 * @return the architecture size or zero if not known (program is null)
	 */
	public int getArchitectureSize() {
		if (program == null) {
			return 0;
		}
		return program.getAddressFactory().getDefaultAddressSpace().getSize();
	}

	/**
	 * Returns whether the symbol should be interpreted as a function
	 * @return {@code true} if should be interpreted as a function
	 */
	boolean shouldInterpretAsFunction() {
		MsCInterpretation control =
			((MicrosoftDemanglerOptions) options).getInterpretation();
		return switch (control) {
			case FUNCTION -> true;
			case NON_FUNCTION -> false;
			case FUNCTION_IF_EXISTS -> getExistingFunction() != null;
			default -> throw new AssertionError("Invalid case");
		};
	}

	/**
	 * Returns the function at the context address
	 * @return the function or null if program or address is null
	 */
	private Function getExistingFunction() {
		if (program == null || address == null) {
			return null;
		}
		return program.getFunctionManager().getFunctionAt(address);
	}

}
