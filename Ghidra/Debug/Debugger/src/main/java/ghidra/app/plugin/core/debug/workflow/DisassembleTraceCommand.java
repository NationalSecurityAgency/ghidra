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
package ghidra.app.plugin.core.debug.workflow;

import ghidra.framework.cmd.TypedBackgroundCommand;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.MathUtilities;
import ghidra.util.task.TaskMonitor;

public class DisassembleTraceCommand extends TypedBackgroundCommand<TraceProgramView> {
	public static DisassembleTraceCommand create(TraceGuestPlatform guest, Address start,
			AddressSetView restrictedSet) {
		return guest == null ? new DisassembleTraceCommand(start, restrictedSet)
				: new DisassembleGuestTraceCommand(guest, start, restrictedSet);
	}

	protected final Address start;
	protected final AddressSetView restrictedSet;

	protected RegisterValue initialContext;
	private AddressSetView disassembled;

	public DisassembleTraceCommand(Address start, AddressSetView restrictedSet) {
		super("Disassemble", true, true, false);
		this.start = start;
		this.restrictedSet = restrictedSet;
	}

	public void setInitialContext(RegisterValue initialContext) {
		this.initialContext = initialContext.getBaseRegisterValue();
	}

	protected Disassembler getDisassembler(TraceProgramView view, TaskMonitor monitor) {
		return Disassembler.getDisassembler(view, monitor, monitor::setMessage);
	}

	protected MemBuffer getBuffer(TraceProgramView view) {
		return new MemoryBufferImpl(view.getMemory(), start);
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
		InstructionSet set = new InstructionSet(view.getAddressFactory());
		set.addBlock(block);
		try {
			return view.getListing().addInstructions(set, true);
		}
		catch (CodeUnitInsertionException e) {
			return new AddressSet();
		}
	}

	@Override
	public boolean applyToTyped(TraceProgramView view, TaskMonitor monitor) {
		Disassembler disassembler = getDisassembler(view, monitor);
		MemBuffer buffer = getBuffer(view);
		int limit = computeLimit();
		InstructionBlock block = disassembler.pseudoDisassembleBlock(buffer, initialContext, limit);
		disassembled = writeBlock(view, block);
		return true;
	}

	public AddressSetView getDisassembledAddressSet() {
		return disassembled;
	}
}
