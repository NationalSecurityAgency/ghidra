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
 * Command object for performing HCS12/XGate disassembly
 */
public class Hcs12DisassembleCommand extends DisassembleCommand {

	private boolean xgMode;

	/**
	* Constructor for Hcs12DisassembleCommand.
	* @param startSet set of addresses to be the start of a disassembly.  The
	* Command object will attempt to start a disassembly at each address in this set.
	* @param restrictedSet addresses that can be disassembled.
	* a null set implies no restrictions
	* @param xgMode pass true if the disassembling in XGATE Mode
	*/
	public Hcs12DisassembleCommand(AddressSetView startSet, AddressSetView restrictedSet,
			boolean xgMode) {
		super("Disassemble " + (xgMode ? "XGate" : "HCS12"), startSet, restrictedSet, true);
		this.xgMode = xgMode;
	}

	/**
	* Constructor for Hcs12DisassembleCommand.
	* @param start address to be the start of a disassembly.
	* @param restrictedSet addresses that can be disassembled.
	* a null set implies no restrictions
	* @param xgMode pass true if the disassembling in XGATE Mode
	*/
	public Hcs12DisassembleCommand(Address start, AddressSetView restrictedSet, boolean xgMode) {
		this(new AddressSet(start, start), restrictedSet, xgMode);
		useDefaultRepeatPatternBehavior = true;
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

		// get the XGATE mode register and set accordingly
		Register xgmodeReg = program.getProgramContext().getRegister("XGATE");
		RegisterValue xgmodeValue = null;

		// if doing xgate, and have no XGmode reg, no way to do disassemble in xgate
		if (xgmodeReg == null) {
			if (xgMode) {
				return false;
			}
		}
		else {
			xgmodeValue = new RegisterValue(xgmodeReg, BigInteger.valueOf(xgMode ? 0x1 : 0x0));
			super.setInitialContext(xgmodeValue);
		}

		int alignment = 1;

		// Set XGate Mode context on undefined code units only
		try {
			if (startSet != null) {

				// Align startSet so that context only affected at possible instruction starts

				AddressSet alignedSet = new AddressSet();
				for (AddressRange range : startSet) {
					Address min = range.getMinAddress();
					long minOfffset = min.getOffset();
					if (minOfffset != min.getOffset()) {
						min = min.getNewAddress(minOfffset);
					}
					Address max = range.getMaxAddress();
					long maxOffset = max.getOffset();
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
