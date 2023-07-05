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
package ghidra.app.plugin.core.debug.stack;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class DynamicMappingException extends EvaluationException {
	private final Program program;
	private final Address address;

	public DynamicMappingException(Program program, Address address) {
		super("Cannot map %s:%s to dynamic adress".formatted(program.getName(), address));
		this.program = program;
		this.address = address;
	}

	public Program getProgram() {
		return program;
	}

	public Address getAddress() {
		return address;
	}
}
