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
package ghidra.app.util.bin.format.elf.extend;

import java.math.BigInteger;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ARM_ElfExtension extends ElfExtension {

	// Elf Program Header Extensions
	public static final ElfProgramHeaderType PT_ARM_EXIDX =
		new ElfProgramHeaderType(0x70000000, "PT_ARM_EXIDX", "Frame unwind information");

	// Elf Section Header Extensions
	public static final ElfSectionHeaderType SHT_ARM_EXIDX =
		new ElfSectionHeaderType(0x70000001, "SHT_ARM_EXIDX", "Exception Index table");
	public static final ElfSectionHeaderType SHT_ARM_PREEMPTMAP = new ElfSectionHeaderType(
		0x70000002, "SHT_ARM_PREEMPTMAP", "BPABI DLL dynamic linking preemption map");
	public static final ElfSectionHeaderType SHT_ARM_ATTRIBUTES = new ElfSectionHeaderType(
		0x70000003, "SHT_ARM_ATTRIBUTES", "Object file compatibility attributes");
	public static final ElfSectionHeaderType SHT_ARM_DEBUGOVERLAY =
		new ElfSectionHeaderType(0x70000004, "SHT_ARM_DEBUGOVERLAY", "See DBGOVL for details");
	public static final ElfSectionHeaderType SHT_ARM_OVERLAYSECTION =
		new ElfSectionHeaderType(0x70000005, "SHT_ARM_OVERLAYSECTION",
			"See Debugging Overlaid Programs (DBGOVL) for details");

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_ARM;
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		Language language = elfLoadHelper.getProgram().getLanguage();
		return canHandle(elfLoadHelper.getElfHeader()) &&
			"ARM".equals(language.getProcessor().toString());
	}

	@Override
	public String getDataTypeSuffix() {
		return "_ARM";
	}

	@Override
	public void processElf(ElfLoadHelper elfLoadHelper, TaskMonitor monitor)
			throws CancelledException {
		Register tmodeRegister = elfLoadHelper.getProgram().getRegister("TMode");
		if (tmodeRegister == null) {
			elfLoadHelper.log("WARNING: TMode register not found - Thumb mode not supported");
		}
		// TODO: markup PT_ARM_EXIDX ?s
	}

	@Override
	public Address creatingFunction(ElfLoadHelper elfLoadHelper, Address functionAddress) {
		Program program = elfLoadHelper.getProgram();
		if ((functionAddress.getOffset() & 1) != 0) {
			Register tmodeRegister = program.getRegister("TMode");
			if (tmodeRegister == null) {
				elfLoadHelper.log("TMode mode not supported, unable to mark address as Thumb: " +
					functionAddress);
				return functionAddress;
			}
			functionAddress = functionAddress.previous(); // align address
			try {
				program.getProgramContext().setValue(tmodeRegister, functionAddress,
					functionAddress, BigInteger.ONE);
			}
			catch (ContextChangeException e) {
				// ignore since should not be instructions at time of import
			}
		}
		if ((functionAddress.getOffset() % 4) == 2) {//The combination bit[1:0] = 0b10 is reserved.
			elfLoadHelper.log("Function address is two bit aligned (reserved per ARM manual): " +
				functionAddress);
		}
		return functionAddress;
	}

	@Override
	public Address evaluateElfSymbol(ElfLoadHelper elfLoadHelper, ElfSymbol elfSymbol,
			Address address, boolean isExternal) {

		if (isExternal) {
			return address;
		}

		Program program = elfLoadHelper.getProgram();

		String symName = elfSymbol.getNameAsString();

		try {
			Register tmodeRegister = program.getRegister("TMode");

			// ELF ARM - tags ARM code with $a and Thumb code with $t
			//
			if (tmodeRegister == null) {
				// Thumb Mode not supported by language
			}
			else if ("$t".equals(symName) || symName.startsWith("$t.")) {
				// is thumb mode
				program.getProgramContext().setValue(tmodeRegister, address, address,
					BigInteger.valueOf(1));
				elfLoadHelper.markAsCode(address);

				// do not retain $t symbols in program due to potential function/thunk naming interference
				elfLoadHelper.setElfSymbolAddress(elfSymbol, address);
				return null;
			}
			else if ("$a".equals(symName) || symName.startsWith("$a.")) {
				// is arm mode
				program.getProgramContext().setValue(tmodeRegister, address, address,
					BigInteger.valueOf(0));
				elfLoadHelper.markAsCode(address);

				// do not retain $a symbols in program due to potential function/thunk naming interference
				elfLoadHelper.setElfSymbolAddress(elfSymbol, address);
				return null;
			}
			else if ("$b".equals(symName)) {
				// don't do anything this is data
			}
			else if ("$d".equals(symName) || symName.startsWith("$d.")) {
				// is data, need to protect as data
				elfLoadHelper.createUndefinedData(address, (int) elfSymbol.getSize());

				// do not retain $d symbols in program due to excessive duplicate symbols
				elfLoadHelper.setElfSymbolAddress(elfSymbol, address);
				return null;
			}
			if (elfSymbol.getType() == ElfSymbol.STT_FUNC) {
				long symVal = address.getOffset();
				if ((symVal & 1) != 0 && tmodeRegister != null) {
					address = address.previous();
					program.getProgramContext().setValue(tmodeRegister, address, address,
						BigInteger.valueOf(1));
				}
			}
		}
		catch (ContextChangeException e) {
			// ignore since should not be instructions at time of import
		}
		return address;
	}

//	@Override
//	public void processGotPlt(ElfLoadHelper elfLoadHelper, TaskMonitor monitor) throws CancelledException {
// TODO override GOT markup.  PLT handled by R_ARM_JUMP_SLOT relocation processing.
//	}

}
