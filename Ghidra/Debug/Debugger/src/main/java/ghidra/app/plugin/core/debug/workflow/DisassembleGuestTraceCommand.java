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

import com.google.common.collect.Range;

import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.InstructionBlock;
import ghidra.program.model.lang.InstructionSet;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.task.TaskMonitor;

public class DisassembleGuestTraceCommand extends DisassembleTraceCommand {
	protected final TraceGuestPlatform guest;

	public DisassembleGuestTraceCommand(TraceGuestPlatform guest, Address start,
			AddressSetView restrictedSet) {
		super(start, restrictedSet);
		this.guest = guest;
	}

	@Override
	protected Disassembler getDisassembler(TraceProgramView view, TaskMonitor monitor) {
		return Disassembler.getDisassembler(guest.getLanguage(), guest.getAddressFactory(), monitor,
			monitor::setMessage);
	}

	@Override
	protected MemBuffer getBuffer(TraceProgramView view) {
		return guest.getMappedMemBuffer(view.getSnap(), guest.mapHostToGuest(start));
	}

	@Override
	protected AddressSetView writeBlock(TraceProgramView view, InstructionBlock block) {
		InstructionSet set = new InstructionSet(guest.getAddressFactory());
		set.addBlock(block);
		return view.getTrace()
				.getCodeManager()
				.instructions()
				.addInstructionSet(Range.atLeast(view.getSnap()), guest, set, true);
	}
}
