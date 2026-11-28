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
package ghidra.app.plugin.core.analysis;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Follows the MIL-STD-1750A interrupt vector table (table VIII, locations 20-3F).
 * Each interrupt has a linkage pointer (where the old MK, SW and IC are stored) and a service
 * pointer to the new MK, SW and IC. The analyzer labels both state blocks and creates a function
 * at each handler's IC. For the executive call (interrupt 5), BEX N takes its IC from the word
 * at service pointer + 2 + N, so up to 16 executive entry points are created.
 */
public class Mil1750aInterruptAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "MIL-STD-1750A Interrupt Vectors";
	private static final String DESCRIPTION =
		"Follows the interrupt linkage and service pointers at 20-3F and creates functions at the " +
			"interrupt handlers and BEX executive entry points.";

	private static final String[] INTERRUPTS = { "POWER_DOWN", "MACHINE_ERROR", "SPARE_2",
		"FLOAT_OVERFLOW", "FIXED_OVERFLOW", "EXEC_CALL", "FLOAT_UNDERFLOW", "TIMER_A", "SPARE_8",
		"TIMER_B", "SPARE_10", "SPARE_11", "IO_LEVEL_1", "SPARE_13", "IO_LEVEL_2", "SPARE_15" };
	private static final int VECTOR_TABLE = 0x20;
	private static final int EXEC_CALL = 5;

	public Mil1750aInterruptAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return "MIL-STD-1750A".equals(program.getLanguage().getProcessor().toString());
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Address table = space.getAddress(VECTOR_TABLE, true);
		if (!set.contains(table) || !initialized(program, table, 0x20) || !plausible(program, table)) {
			return false;
		}
		for (int n = 0; n < INTERRUPTS.length; n++) {
			monitor.checkCancelled();
			String prefix = String.format("INT%02d_%s", n, INTERRUPTS[n]);
			Address lpAddr = space.getAddress(VECTOR_TABLE + 2 * n, true);
			Address spAddr = word(lpAddr, 1);
			markPointer(program, lpAddr);
			markPointer(program, spAddr);
			Address oldState = target(program, lpAddr);
			if (oldState != null && initialized(program, oldState, 3)) {
				label(program, oldState, prefix + "_OLD_STATE", 3);
			}
			Address newState = target(program, spAddr);
			if (newState == null || !initialized(program, newState, 3)) {
				continue;
			}
			label(program, newState, prefix + "_NEW_STATE", n == EXEC_CALL ? 18 : 3);
			if (n == EXEC_CALL) {
				for (int k = 0; k < 16; k++) {
					Address icAddr = word(newState, 2 + k);
					if (initialized(program, icAddr, 1)) {
						entry(program, target(program, icAddr), String.format("BEX_%d", k), monitor);
					}
				}
			}
			else {
				entry(program, target(program, word(newState, 2)), prefix + "_HANDLER", monitor);
			}
		}
		return true;
	}

	/**
	 * Checks that 20-3F hold a vector table and not code or data: every used service pointer must
	 * point to a new state (MK, SW, IC) in initialized memory w/ the reserved SW bits 4-7 clear.
	 */
	private static boolean plausible(Program program, Address table) {
		int used = 0;
		for (int n = 0; n < INTERRUPTS.length; n++) {
			Address newState = target(program, word(table, 2 * n + 1));
			if (newState == null) {
				continue;
			}
			if (!initialized(program, newState, 3)) {
				return false;
			}
			try {
				int sw = program.getMemory().getShort(word(newState, 1)) & 0xffff;
				if ((sw & 0x0f00) != 0) {
					return false;
				}
			}
			catch (MemoryAccessException e) {
				return false;
			}
			used++;
		}
		return used > 0;
	}

	/** The address n 16-bit words after addr (Address offsets count bytes). */
	private static Address word(Address addr, int n) {
		return addr.addWrap((long) n * addr.getAddressSpace().getAddressableUnitSize());
	}

	private static boolean initialized(Program program, Address start, int words) {
		Memory mem = program.getMemory();
		for (int i = 0; i < words; i++) {
			if (!mem.getAllInitializedAddressSet().contains(word(start, i))) {
				return false;
			}
		}
		return true;
	}

	private static Address target(Program program, Address ptr) {
		try {
			int w = program.getMemory().getShort(ptr) & 0xffff;
			if (w == 0 || w == 0xffff) {
				return null;    // unused or erased entry
			}
			return ptr.getAddressSpace().getAddress(w, true);
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	private static void markPointer(Program program, Address addr) {
		Listing listing = program.getListing();
		if (listing.getDefinedDataAt(addr) != null || listing.getInstructionAt(addr) != null) {
			return;
		}
		try {
			listing.createData(addr, PointerDataType.dataType);
		}
		catch (CodeUnitInsertionException e) {
			// leave it undefined if something else is already there
		}
	}

	private static void label(Program program, Address addr, String name, int words) {
		SymbolTable st = program.getSymbolTable();
		try {
			st.createLabel(addr, name, SourceType.ANALYSIS);
		}
		catch (InvalidInputException e) {
			return;
		}
		Listing listing = program.getListing();
		for (int i = 0; i < words; i++) {
			Address a = word(addr, i);
			if (listing.getDefinedDataAt(a) == null && listing.getInstructionAt(a) == null) {
				try {
					listing.createData(a, WordDataType.dataType);
				}
				catch (CodeUnitInsertionException e) {
					// keep going
				}
			}
		}
	}

	private static void entry(Program program, Address addr, String name, TaskMonitor monitor) {
		if (addr == null || !initialized(program, addr, 1)) {
			return;
		}
		if (program.getListing().getDefinedDataContaining(addr) != null) {
			return;
		}
		program.getSymbolTable().addExternalEntryPoint(addr);
		new DisassembleCommand(addr, null, true).applyTo(program, monitor);
		if (program.getFunctionManager().getFunctionAt(addr) == null) {
			new CreateFunctionCmd(name, addr, null, SourceType.ANALYSIS).applyTo(program, monitor);
		}
	}
}
