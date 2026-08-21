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

import java.util.*;

import ghidra.lisa.pcode.locations.InstLocation;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import it.unive.lisa.program.cfg.CodeLocation;

public class InstructionContext {

	protected Function function;
	protected Instruction inst;
	protected List<StatementContext> ops;
	protected InstLocation loc;

	public InstructionContext(Function function, Instruction inst) {
		this.function = function;
		this.inst = inst;
		ops = new ArrayList<>();
		for (PcodeOp op : inst.getPcode()) {
			StatementContext ctx = new StatementContext(inst, op);
			ops.add(ctx);
		}
		loc = new InstLocation(function, inst.getAddress());
	}

	public InstructionContext() {
		// For HighInstructionContext
	}

	public Collection<StatementContext> getPcodeOps() {
		return ops;
	}

	public StatementContext getPcodeOp(int i) {
		return ops.get(i);
	}

	public InstructionContext next() {
		if (inst == null) {
			return null;
		}
		Listing listing = inst.getProgram().getListing();
		Address nextAddress = inst.getAddress().add(inst.getLength());
		Instruction next = listing.getInstructionAt(nextAddress);
		return next == null ? null : new InstructionContext(function, next);
	}

	public CodeLocation location() {
		return loc;
	}

}
