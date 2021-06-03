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
package ghidra.app.cmd.disassemble;

import java.math.BigInteger;

import ghidra.framework.model.DomainObject;
import ghidra.program.disassemble.DisassemblerContextImpl;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Command object for performing PPC disassembly when VLE instructions are supported.
 */
public class PowerPCDisassembleCommand extends DisassembleCommand {

	private boolean vleMode;

	/**
	* Constructor for PowerPCDisassembleCommand.
	* @param startSet set of addresses to be the start of a disassembly.  The
	* Command object will attempt to start a disassembly at each address in this set.
	* @param restrictedSet addresses that can be disassembled.
	* a null set implies no restrictions
	* @param vleMode pass true if the disassembling in PowerISA VLE Mode, otherwise
	* normal disassembly will be performed.
	*/
	public PowerPCDisassembleCommand(AddressSetView startSet, AddressSetView restrictedSet,
			boolean vleMode) {
		super(startSet, restrictedSet, true);
		this.vleMode = vleMode;
	}

	/**
	* Constructor for PowerPCDisassembleCommand.
	* @param start address to be the start of a disassembly.
	* @param restrictedSet addresses that can be disassembled.
	* a null set implies no restrictions
	* @param vleMode pass true if the disassembling in PowerISA VLE Mode, otherwise
	* normal disassembly will be performed.
	*/
	public PowerPCDisassembleCommand(Address start, AddressSetView restrictedSet, boolean vleMode) {
		super(start, restrictedSet, true);
		this.vleMode = vleMode;
	}

	@Override
	public String getName() {
		return "Disassemble " + (vleMode ? "PPC-VLE" : "PPC");
	}

	@Override
	public void setSeedContext(DisassemblerContextImpl seedContext) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setInitialContext(RegisterValue initialContextValue) {
		throw new UnsupportedOperationException();
	}

	@Override
	synchronized public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		Program program = (Program) obj;

		disassemblyPerformed = false;
		unalignedStart = false;

		// get the M16_MODE register and set accordingly
		Register vlemodeReg = program.getProgramContext().getRegister("vle");

		// if doing mips, and have no M16_MODE reg, no way to do disassemble in mips16
		if (vlemodeReg == null) {
			if (vleMode) {
				setStatusMsg("PowerISA VLE mode not supported");
				return false;
			}
			return super.applyTo(obj, monitor);
		}

		RegisterValue vlemodeValue =
			new RegisterValue(vlemodeReg, BigInteger.valueOf(vleMode ? 0x1 : 0x0));
		super.setInitialContext(vlemodeValue);

		int alignment = (vleMode ? 2 : 4);
		long alignMask = vleMode ? ~1 : ~3;

		// Set M16_MODE context on undefined code units only
		try {
			if (startSet != null) {

				// Align startSet so that context only affected at possible instruction starts

				AddressSet alignedSet = new AddressSet();
				for (AddressRange range : startSet) {
					Address min = range.getMinAddress();
					long minOfffset = min.getOffset() & alignMask;
					if (minOfffset != min.getOffset()) {
						min = min.getNewAddress(minOfffset);
					}
					Address max = range.getMaxAddress();
					long maxOffset = max.getOffset() & alignMask;
					if (maxOffset < minOfffset) {
						// skip short unaligned range
						continue;
					}
					if (maxOffset != max.getOffset()) {
						max = max.getNewAddress(maxOffset);
					}
					alignedSet.addRange(min, max);
				}
				if (alignedSet.isEmpty()) {
					unalignedStart = true;
					return false; // alignedSet does not contain any aligned starts
				}
				startSet = program.getListing().getUndefinedRanges(alignedSet, true, monitor);
				if (startSet.isEmpty()) {
					return true; // startSet does not contain any aligned undefined starts 
				}
			}
		}
		catch (CancelledException e) {
			return true;
		}

		return doDisassembly(monitor, program, alignment);
	}
}
