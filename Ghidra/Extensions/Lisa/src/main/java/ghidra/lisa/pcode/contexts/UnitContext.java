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
package ghidra.lisa.pcode.contexts;

import ghidra.lisa.pcode.PcodeFrontend;
import ghidra.lisa.pcode.locations.InstLocation;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import it.unive.lisa.program.CodeUnit;
import it.unive.lisa.program.Program;
import it.unive.lisa.program.SyntheticLocation;
import it.unive.lisa.program.cfg.CodeLocation;

public class UnitContext {

	private PcodeFrontend frontend;
	private Function function;
	private CodeUnit unit;
	private Address start;

	public UnitContext(PcodeFrontend frontend, Program program, Function f) {
		this.frontend = frontend;
		this.function = f;
		unit = new CodeUnit(SyntheticLocation.INSTANCE, program, f.getName());
		start = function.getEntryPoint();
	}

	public UnitContext(PcodeFrontend frontend, Program program, Function f, Address entry) {
		this.frontend = frontend;
		this.function = f;
		unit = new CodeUnit(SyntheticLocation.INSTANCE, program,
			f.getName() + ":" + f.getEntryPoint());
		start = entry;
	}

	public PcodeFrontend getFrontend() {
		return frontend;
	}

	public CodeUnit unit() {
		return unit;
	}

	public String getText() {
		return function.getName();
	}

	public boolean isFinal() {
		return false;
	}

	public Listing getListing() {
		return function.getProgram().getListing();
	}

	public CodeLocation location() {
		return new InstLocation(function, start);
	}

	public Function function() {
		return function;
	}

	public InstructionContext entry() {
		Instruction inst = getListing().getInstructionAt(start);
		if (inst == null) {
			inst = getListing().getInstructionAfter(start);
		}
		return inst == null ? null : new InstructionContext(function, inst);
	}

	public boolean contains(Address target) {
		return function.getBody().contains(target);
	}
}
