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
package ghidra.app.util.demangler;

import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * A simple class to contain the context of a mangled symbol for demangling
 */
public class MangledContext {

	protected Program program;
	protected DemanglerOptions options;
	protected String mangled;
	protected Address address;

	/**
	 * Constructor for mangled context
	 * @param program the program; can be null
	 * @param options the demangler options
	 * @param mangled the mangled string
	 * @param address the address; can be null
	 */
	public MangledContext(Program program, DemanglerOptions options, String mangled,
			Address address) {
		this.program = program;
		this.options = Objects.requireNonNull(options, "Options cannot be null");
		this.mangled = Objects.requireNonNull(mangled, "Mangled cannot be null");
		this.address = address;
	}

	/**
	 * Returns the program
	 * @return the program; can be null
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * Returns the demangler options
	 * @return the options
	 */
	public DemanglerOptions getOptions() {
		return options;
	}

	/**
	 * Returns the mangled string
	 * @return the mangled string
	 */
	public String getMangled() {
		return mangled;
	}

	/**
	 * Returns the address
	 * @return the address; can be null
	 */
	public Address getAddress() {
		return address;
	}

}
