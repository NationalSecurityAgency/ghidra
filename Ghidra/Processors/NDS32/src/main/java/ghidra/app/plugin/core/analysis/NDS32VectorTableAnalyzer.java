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
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Detects the NDS32 exception/interrupt vector table at the load base of raw binaries
 * and creates an entry point at each vector slot.  The table is N entries (default 16,
 * IVB.NIVIC) of ESZ bytes each (default 4, IVB.ESZ).  Runs at FORMAT_ANALYSIS so
 * BLOCK_ANALYSIS has entry points to disassemble from.
 */
public class NDS32VectorTableAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "NDS32 Vector Table";
	private static final String DESCRIPTION =
		"Recognizes the NDS32 exception/interrupt vector table at the load " +
			"base address and creates _start entry points at each vector " +
			"slot so disassembly can follow into the reset and exception " +
			"handlers.  Entry size matches IVB.ESZ; vector count matches " +
			"IVB.NIVIC.";
	private static final String PROCESSOR_NAME = "NDS32";

	private static final String OPT_BASE_ADDRESS = "Base address (hex, blank = auto)";
	private static final String OPT_BASE_ADDRESS_DESC =
		"Address where the vector table starts (IVB.IVBASE).  Leave blank " +
			"to use the lowest mapped address.";

	private static final String OPT_ENTRY_SIZE = "Vector entry size (bytes)";
	private static final String OPT_ENTRY_SIZE_DESC =
		"Bytes per vector table entry (IVB.ESZ): 4, 16, 64, or 256.";
	private static final int OPT_ENTRY_SIZE_DEFAULT = 4;

	private static final String OPT_VECTOR_COUNT = "Vector count (0 = auto-detect)";
	private static final String OPT_VECTOR_COUNT_DESC =
		"Number of vector slots (IVB.NIVIC).  Default 16.  Set to 0 to auto-detect " +
			"by walking valid 'j'/'jal' entries from the base address.";
	private static final int OPT_VECTOR_COUNT_DEFAULT = 16;

	private int entrySize = OPT_ENTRY_SIZE_DEFAULT;
	private int vectorCount = OPT_VECTOR_COUNT_DEFAULT;
	private volatile Long manualBase = null;

	public NDS32VectorTableAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPT_BASE_ADDRESS, "", null, OPT_BASE_ADDRESS_DESC);
		options.registerOption(OPT_ENTRY_SIZE, OPT_ENTRY_SIZE_DEFAULT, null,
			OPT_ENTRY_SIZE_DESC);
		options.registerOption(OPT_VECTOR_COUNT, OPT_VECTOR_COUNT_DEFAULT, null,
			OPT_VECTOR_COUNT_DESC);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		entrySize = options.getInt(OPT_ENTRY_SIZE, OPT_ENTRY_SIZE_DEFAULT);
		vectorCount = options.getInt(OPT_VECTOR_COUNT, OPT_VECTOR_COUNT_DEFAULT);
		manualBase = parseHex(options.getString(OPT_BASE_ADDRESS, ""));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		// optionsChanged() isn't guaranteed to have fired before analysis runs.
		Options opts = program.getOptions(Program.ANALYSIS_PROPERTIES);
		entrySize = opts.getInt(NAME + "." + OPT_ENTRY_SIZE, OPT_ENTRY_SIZE_DEFAULT);
		vectorCount = opts.getInt(NAME + "." + OPT_VECTOR_COUNT, OPT_VECTOR_COUNT_DEFAULT);
		manualBase = parseHex(opts.getString(NAME + "." + OPT_BASE_ADDRESS, ""));

		if (!isValidEntrySize(entrySize)) {
			log.appendMsg(NAME, "Invalid entry size " + entrySize +
				"; expected 4/16/64/256. Skipping.");
			return false;
		}

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Memory mem = program.getMemory();
		Address base = resolveBaseAddress(program, space);
		if (base == null) {
			log.appendMsg(NAME,
				"Could not determine vector table base; set '" + OPT_BASE_ADDRESS +
					"' explicitly or load the binary at a sensible base.");
			return false;
		}

		int slotsToTry = vectorCount > 0 ? vectorCount : 64;
		int validSlots = countValidSlots(mem, base, entrySize, slotsToTry);
		if (validSlots < 1) {
			log.appendMsg(NAME, String.format(
				"No valid vector entries found at %s (entry size %d). Skipping.",
				base, entrySize));
			return false;
		}
		int slots = vectorCount > 0 ? vectorCount : validSlots;

		SymbolTable symTable = program.getSymbolTable();
		try {
			base.add((long) slots * entrySize - 1);
		}
		catch (Exception e) {
			log.appendMsg(NAME, "Vector table extends past mapped memory: " + e.getMessage());
			return false;
		}

		if (!symTable.isExternalEntryPoint(base)) {
			try {
				symTable.createLabel(base, "_start", SourceType.ANALYSIS);
			}
			catch (InvalidInputException e) {
				// proceed regardless
			}
		}
		for (int i = 0; i < slots; i++) {
			Address slot;
			try {
				slot = base.add((long) i * entrySize);
			}
			catch (Exception e) {
				break;
			}
			symTable.addExternalEntryPoint(slot);
		}

		Msg.info(this, String.format(
			"%s: vector table at %s (entry size %d, %d slot(s)); created entry points " +
				"(auto-detected validity: %d slot(s))",
			NAME, base, entrySize, slots, validSlots));

		// Batch all slots into one DisassembleCommand to avoid per-slot event overhead.
		AddressSet starts = new AddressSet();
		for (int i = 0; i < slots; i++) {
			try {
				starts.add(base.add((long) i * entrySize));
			}
			catch (Exception e) {
				break;
			}
		}
		if (!starts.isEmpty()) {
			new DisassembleCommand(starts, null, true).applyTo(program, monitor);
		}

		return true;
	}

	// Priority: explicit OPT_BASE_ADDRESS, lowest initialized executable block,
	// lowest initialized block.
	private Address resolveBaseAddress(Program program, AddressSpace space) {
		if (manualBase != null) {
			try {
				return space.getAddress(manualBase);
			}
			catch (Exception e) {
				// fall through to auto-detect
			}
		}
		MemoryBlock best = null;
		for (MemoryBlock b : program.getMemory().getBlocks()) {
			if (b.getStart().getAddressSpace() != space) {
				continue;
			}
			if (!b.isInitialized() || !b.isExecute()) {
				continue;
			}
			if (best == null || b.getStart().compareTo(best.getStart()) < 0) {
				best = b;
			}
		}
		if (best == null) {
			for (MemoryBlock b : program.getMemory().getBlocks()) {
				if (b.getStart().getAddressSpace() != space) {
					continue;
				}
				if (!b.isInitialized()) {
					continue;
				}
				if (best == null || b.getStart().compareTo(best.getStart()) < 0) {
					best = b;
				}
			}
		}
		return best == null ? null : best.getStart();
	}

	private static Long parseHex(String raw) {
		if (raw == null) return null;
		raw = raw.trim();
		if (raw.isEmpty()) return null;
		if (raw.startsWith("0x") || raw.startsWith("0X")) raw = raw.substring(2);
		try {
			return Long.parseLong(raw, 16);
		}
		catch (NumberFormatException e) {
			return null;
		}
	}

	private static boolean isValidEntrySize(int sz) {
		return sz == 4 || sz == 16 || sz == 64 || sz == 256;
	}

	private static int countValidSlots(Memory mem, Address base, int entrySize, int max) {
		int valid = 0;
		for (int i = 0; i < max; i++) {
			Address slot;
			try {
				slot = base.add((long) i * entrySize);
			}
			catch (Exception e) {
				break;
			}
			byte[] bytes = new byte[Math.min(entrySize, 4)];
			try {
				if (mem.getBytes(slot, bytes) != bytes.length) {
					break;
				}
			}
			catch (Exception e) {
				break;
			}
			if (!looksLikeVectorEntry(bytes, entrySize)) {
				break;
			}
			valid++;
		}
		return valid;
	}

	// For ESZ=4: byte 0 must be 0x48 (j) or 0x49 (jal).  For larger ESZ: reject
	// all-zero / all-0xff padding.
	private static boolean looksLikeVectorEntry(byte[] bytes, int entrySize) {
		if (entrySize == 4) {
			int b0 = bytes[0] & 0xff;
			if (b0 != 0x48 && b0 != 0x49) {
				return false;
			}
			boolean allZero = true;
			boolean allOnes = true;
			for (byte b : bytes) {
				if (b != 0x00) {
					allZero = false;
				}
				if ((b & 0xff) != 0xff) {
					allOnes = false;
				}
			}
			return !allZero && !allOnes;
		}
		int b0 = bytes[0] & 0xff;
		int b1 = bytes[1] & 0xff;
		if ((b0 == 0x00 && b1 == 0x00) || (b0 == 0xff && b1 == 0xff)) {
			return false;
		}
		return true;
	}
}
