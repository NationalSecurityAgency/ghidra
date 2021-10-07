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

import javax.help.UnsupportedOperationException;

import ghidra.framework.model.DomainObject;
import ghidra.program.disassemble.DisassemblerContextImpl;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Command object for performing 64-/32-bit x86 disassembly
 * 
 * <p>
 * This generally only comes up when debugging, since there can be multiple images loaded by an
 * x86-64 target. For WoW64, the images may be mixed. Thus, this command allows you to disassemble
 * 64-bit or 32-bit instructions whenever the language is set to 64-bit x86.
 * 
 * <p>
 * <b>WARNING:</b> If used in static programs, i.e., not debug traces, there are some potential
 * remaining issues, particularly dealing with stored context and follow-on disassembly -- typically
 * called for by the analyzers. In most cases, this does not matter, since mixed 64- and 32-bit code
 * in a single image is likely a niche case and can be handled via careful commands from the user.
 * Nevertheless, TODO: Rework x86-64 analyzers to call the correct mode of disassembly.
 */
public class X86_64DisassembleCommand extends DisassembleCommand {

	private final boolean size32Mode;

	/**
	 * Constructor for X86_64DisassembleCommand.
	 * 
	 * @param startSet set of addresses to be the start of disassembly. The Command object will
	 *            attempt to start a disassembly at each address in this set.
	 * @param restrictedSet addresses that can be disassembled. a null set implies no restrictions.
	 * @param size32Mode pass true if disassembling in 32-bit compatibility mode, otherwise normal
	 *            64-bit disassembly will be performed.
	 */
	public X86_64DisassembleCommand(AddressSetView startSet, AddressSetView restrictedSet,
			boolean size32Mode) {
		super(startSet, restrictedSet, true);
		this.size32Mode = size32Mode;
	}

	/**
	 * Constructor for X86_64DisassembleCommand.
	 * 
	 * @param start address to be the start of a disassembly.
	 * @param restrictedSet addresses that can be disassembled. a null set implies no restrictions.
	 * @param size32Mode pass true if disassembling in 32-bit compatibility mode, otherwise normal
	 *            64-bit disassembly will be performed.
	 */
	public X86_64DisassembleCommand(Address start, AddressSetView restrictedSet,
			boolean size32Mode) {
		super(start, restrictedSet, true);
		this.size32Mode = size32Mode;
	}

	@Override
	public String getName() {
		return "Disassemble " + (size32Mode ? "32" : "64") + "-bit x86";
	}

	@Override
	public void setSeedContext(DisassemblerContextImpl seedContext) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setInitialContext(RegisterValue initialContextValue) {
		throw new UnsupportedOperationException();
	}

	public static AddressSet alignSet(int alignment, AddressSetView set)
			throws CancelledException {
		AddressSet result = new AddressSet();
		for (AddressRange range : set) {
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
			result.addRange(min, max);
		}
		return result;
	}

	@Override
	synchronized public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		Program program = (Program) obj;

		disassemblyPerformed = false;
		unalignedStart = false;

		// get the longMode register and set accordingly
		ProgramContext context = program.getProgramContext();
		Register longModeReg = context.getRegister("longMode");

		// Indicates we're not x86-64, or the spec has changed
		if (longModeReg == null) {
			languageError = "Requires x86:LE:64:default";
			return false;
		}
		RegisterValue ctx = new RegisterValue(context.getBaseContextRegister())
				.assign(longModeReg, size32Mode ? BigInteger.ZERO : BigInteger.ONE);

		super.setInitialContext(ctx);

		try {
			if (startSet != null) {
				// This is identity, no?
				AddressSet alignedSet = alignSet(1, startSet);
				if (alignedSet.isEmpty()) {
					unalignedStart = true;
					return false;
				}
				startSet = program.getListing().getUndefinedRanges(alignedSet, true, monitor);
				if (startSet.isEmpty()) {
					return true;
				}
			}
		}
		catch (CancelledException e) {
			return true;
		}

		return doDisassembly(monitor, program, 1);
	}
}
