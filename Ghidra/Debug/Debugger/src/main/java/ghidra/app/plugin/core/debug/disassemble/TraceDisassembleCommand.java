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
package ghidra.app.plugin.core.debug.disassemble;

import ghidra.framework.cmd.TypedBackgroundCommand;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.MathUtilities;
import ghidra.util.task.TaskMonitor;

public class TraceDisassembleCommand extends TypedBackgroundCommand<TraceProgramView> {

	protected final TracePlatform platform;
	protected final Address start;
	protected final AddressSetView restrictedSet;

	protected RegisterValue initialContext;
	private AddressSetView disassembled;

	public TraceDisassembleCommand(TracePlatform platform, Address start,
			AddressSetView restrictedSet) {
		super("Disassemble", true, true, false);
		this.platform = platform;
		this.start = start;
		this.restrictedSet = restrictedSet;
	}

	public void setInitialContext(RegisterValue initialContext) {
		this.initialContext = initialContext.getBaseRegisterValue();
	}

	protected Disassembler getDisassembler(TraceProgramView view, TaskMonitor monitor) {
		return Disassembler.getDisassembler(platform.getLanguage(), platform.getAddressFactory(),
			monitor, monitor::setMessage);
	}

	protected MemBuffer getBuffer(TraceProgramView view) {
		return platform.getMappedMemBuffer(view.getSnap(), platform.mapHostToGuest(start));
	}

	protected int computeLimit() {
		AddressRange range = restrictedSet.getRangeContaining(start);
		if (range == null) {
			return 1;
		}
		return MathUtilities.unsignedMin(range.getMaxAddress().subtract(start) + 1,
			Integer.MAX_VALUE);
	}

	protected AddressSetView writeBlock(TraceProgramView view, InstructionBlock block) {
		InstructionSet set = new InstructionSet(platform.getAddressFactory());
		set.addBlock(block);
		return view.getTrace()
				.getCodeManager()
				.instructions()
				.addInstructionSet(Lifespan.nowOn(view.getSnap()), platform, set, true);
	}

	@Override
	public boolean applyToTyped(TraceProgramView view, TaskMonitor monitor) {
		Disassembler disassembler = getDisassembler(view, monitor);
		MemBuffer buffer = getBuffer(view);
		int limit = computeLimit();
		// TODO: limit is actually instruction count, not byte count :'(
		InstructionBlock block = disassembler.pseudoDisassembleBlock(buffer, initialContext, limit);
		if (block == null) {
			return true; // Alignment issue. Just go silently.
		}
		InstructionBlock filtered = new InstructionBlock(block.getStartAddress());
		for (Instruction ins : block) {
			if (restrictedSet.contains(ins.getMaxAddress())) {
				filtered.addInstruction(ins);
			}
			else {
				break;
			}
		}
		disassembled = writeBlock(view, filtered);
		return true;
	}

	public AddressSetView getDisassembledAddressSet() {
		return disassembled;
	}
}
