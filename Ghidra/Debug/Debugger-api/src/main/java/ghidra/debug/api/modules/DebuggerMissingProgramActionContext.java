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
package ghidra.debug.api.modules;

import java.util.Objects;

import docking.DefaultActionContext;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;

public class DebuggerMissingProgramActionContext extends DefaultActionContext {

	public static Address getMappingProbeAddress(Program program) {
		if (program == null) {
			return null;
		}
		AddressIterator eepi = program.getSymbolTable().getExternalEntryPointIterator();
		if (eepi.hasNext()) {
			return eepi.next();
		}
		InstructionIterator ii = program.getListing().getInstructions(true);
		if (ii.hasNext()) {
			return ii.next().getAddress();
		}
		AddressSetView es = program.getMemory().getExecuteSet();
		if (!es.isEmpty()) {
			return es.getMinAddress();
		}
		if (!program.getMemory().isEmpty()) {
			return program.getMinAddress();
		}
		return null;
	}

	private final Trace trace;
	private final Program program;
	private final int hashCode;

	private Address probe;

	public DebuggerMissingProgramActionContext(Trace trace, Program program) {
		this.trace = Objects.requireNonNull(trace);
		this.program = Objects.requireNonNull(program);
		this.hashCode = Objects.hash(getClass(), trace, program);
	}

	public Trace getTrace() {
		return trace;
	}

	public Program getProgram() {
		return program;
	}

	@Override
	public int hashCode() {
		return hashCode;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof DebuggerMissingProgramActionContext that)) {
			return false;
		}
		if (!this.trace.equals(that.trace)) {
			return false;
		}
		if (!this.program.equals(that.program)) {
			return false;
		}
		return true;
	}

	public Address getMappingProbeAddress() {
		if (probe == null) {
			probe = getMappingProbeAddress(program);
		}
		return probe;
	}
}
