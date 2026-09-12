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

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeEmulationCallbacks;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.pcode.exec.PcodeStateCallbacks;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Traces the CRT/startup sequence with the pcode emulator and commits memory
 * writes that land in currently-uninitialized blocks back to the program.  This
 * populates RW data segments from .data-copy / .bss-zero loops so subsequent
 * analysis can resolve constants stored there (e.g. MT7663 loads ITB from a
 * .data slot that is uninitialized in the ROM image).  Default stop condition
 * is branch-to-self or the instruction cap.
 */
public class NDS32DataInitAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "NDS32 Data Init Trace";
	private static final String DESCRIPTION =
		"Emulates the CRT/startup sequence from the reset vector and " +
			"applies its memory writes (typically .data copies and .bss " +
			"zeroing) to currently-uninitialized memory blocks.  This " +
			"populates RW segments that depend on runtime initialization " +
			"so subsequent analysis can resolve constants stored there.";
	private static final String PROCESSOR_NAME = "NDS32";

	private static final String OPT_INSTR_CAP = "Instruction cap";
	private static final String OPT_STOP_ADDR = "Init stop address (hex, blank = auto)";
	private static final String OPT_RESET_ADDR = "Reset vector address (hex, blank = symbol)";
	private static final String OPT_QUIESCENT_STEPS = "Quiescent-stop step count";
	private static final String OPT_MMIO_OVERRIDES = "MMIO mock overrides";
	private static final String OPT_MMIO_AUTODETECT = "Auto-detect MMIO polling";

	private static final int DEFAULT_INSTR_CAP = 1_000_000;
	private static final int DEFAULT_QUIESCENT_STEPS = 50_000;
	// MMIO mock + auto-detect is restricted to the upper half of the address
	// space so SRAM/DLM reads remain observable as "not yet initialized".
	private static final long MMIO_THRESHOLD = 0x80000000L;
	private static final int AUTODETECT_READ_THRESHOLD = 100;
	private static final int AUTODETECT_STEP_WINDOW = 1000;
	private static final String BOOKMARK_CATEGORY = "NDS32 Data Init";

	public NDS32DataInitAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// Opt-in: emulator runs can be expensive.
		setDefaultEnablement(false);
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.before());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPT_INSTR_CAP, DEFAULT_INSTR_CAP, null,
			"Maximum instructions to emulate before bailing out.  Default 1,000,000.");
		options.registerOption(OPT_STOP_ADDR, "", null,
			"Stop emulation when the PC reaches this address (hex).  Leave blank to " +
				"use auto-stop on first branch-to-self.");
		options.registerOption(OPT_RESET_ADDR, "", null,
			"Reset vector address (hex).  Leave blank to look up a default symbol " +
				"named 'Reset', 'RESET', '_start', or '_RESET'.");
		options.registerOption(OPT_QUIESCENT_STEPS, DEFAULT_QUIESCENT_STEPS, null,
			"Stop emulation after this many consecutive steps with no new writes " +
				"to a sink (uninitialized) block; indicates init is done.  Set to 0 to disable.");
		options.registerOption(OPT_MMIO_OVERRIDES, "", null,
			"Comma-separated MMIO mock overrides for addresses >=0x80000000.  " +
				"Each entry is ADDR=BEHAVIOR.  BEHAVIOR is one of:\n" +
				"  const:VAL     return the constant VAL on every read\n" +
				"  count[:STEP]  return a counter that starts at 0 and grows by " +
				"STEP per read (default STEP=1)\n" +
				"Example: 0x81030000=const:0x80000000, 0x81030534=count:0x100\n" +
				"All addresses and values are interpreted as hex.");
		options.registerOption(OPT_MMIO_AUTODETECT, true, null,
			"If enabled, any unmocked MMIO address (>=0x80000000) that is read " +
				AUTODETECT_READ_THRESHOLD + "+ times within " +
				AUTODETECT_STEP_WINDOW + " steps is automatically promoted to a " +
				"saturating counter, which lets timeout-style polling loops " +
				"exit instead of running for their full count.");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		Options opts = program.getOptions(Program.ANALYSIS_PROPERTIES);
		int instrCap = opts.getInt(NAME + "." + OPT_INSTR_CAP, DEFAULT_INSTR_CAP);
		String stopAddrRaw = opts.getString(NAME + "." + OPT_STOP_ADDR, "").trim();
		String resetAddrRaw = opts.getString(NAME + "." + OPT_RESET_ADDR, "").trim();
		int quiescentStops = opts.getInt(NAME + "." + OPT_QUIESCENT_STEPS,
			DEFAULT_QUIESCENT_STEPS);
		String mmioOverridesRaw = opts.getString(NAME + "." + OPT_MMIO_OVERRIDES, "").trim();
		boolean mmioAutodetect = opts.getBoolean(NAME + "." + OPT_MMIO_AUTODETECT, true);

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Address resetAddr = resolveResetAddress(program, resetAddrRaw, space, log);
		if (resetAddr == null) {
			log.appendMsg(NAME, "No reset vector found; skipping.  Set the '" +
				OPT_RESET_ADDR + "' option to an explicit hex value to override.");
			return true;
		}
		Address stopAddr = parseHex(stopAddrRaw, space);

		List<MemoryBlock> uninit = new ArrayList<>();
		for (MemoryBlock b : program.getMemory().getBlocks()) {
			if (!b.isInitialized()) {
				uninit.add(b);
			}
		}
		if (uninit.isEmpty()) {
			log.appendMsg(NAME,
				"No uninitialized memory blocks; init trace would have nothing to commit.");
			return true;
		}
		AddressSet sinkRange = new AddressSet();
		for (MemoryBlock b : uninit) {
			sinkRange.add(b.getStart(), b.getEnd());
		}

		Msg.info(this, String.format(
			"%s: Tracing init from %s (instruction cap %d%s%s)",
			NAME, resetAddr, instrCap,
			stopAddr == null ? ", auto-stop on self-loop" : ", stop at " + stopAddr,
			uninit.size() > 0 ? "; capturing writes to " + describeBlocks(uninit) : ""));

		CaptureCallbacks cb = new CaptureCallbacks(program, sinkRange);
		Map<Long, MmioMock> userMocks = parseMmioOverrides(mmioOverridesRaw, log);
		cb.installMmioMocks(userMocks, mmioAutodetect,
			program.getLanguage().isBigEndian());
		PcodeEmulator emu = new PcodeEmulator(program.getLanguage(), cb);

		seedContextRegisters(program, emu);

		PcodeThread<byte[]> thread = emu.newThread("init");
		thread.overrideCounter(resetAddr);

		int steps = 0;
		Address prevPc = null;
		String stopReason = "instruction cap reached";
		int lastWriteCount = 0;
		int quiescentRun = 0;
		try {
			while (steps < instrCap) {
				monitor.checkCancelled();
				Address pc = thread.getCounter();
				if (stopAddr != null && pc.equals(stopAddr)) {
					stopReason = "reached stop address " + stopAddr;
					break;
				}
				if (prevPc != null && pc.equals(prevPc)) {
					stopReason = "branch-to-self detected at " + pc;
					break;
				}
				prevPc = pc;
				try {
					thread.stepInstruction();
				}
				catch (Exception e) {
					stopReason = "emulator error at " + pc + ": " + e.getMessage();
					break;
				}
				steps++;
				int now = cb.captureCount();
				if (now > lastWriteCount) {
					lastWriteCount = now;
					quiescentRun = 0;
				}
				else if (quiescentStops > 0) {
					quiescentRun++;
					if (quiescentRun >= quiescentStops) {
						stopReason = String.format(
							"quiescent: no new writes for %d steps (init done)",
							quiescentStops);
						break;
					}
				}
				if ((steps % 100_000) == 0) {
					monitor.setMessage(String.format(
						"NDS32 init trace: %d steps, %d writes captured", steps,
						cb.captureCount()));
				}
			}
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Exception e) {
			stopReason = "exception during emulation: " + e.getMessage();
		}

		Msg.info(this, String.format(
			"%s: Emulation stopped after %d step(s): %s.  %d distinct ranges captured.",
			NAME, steps, stopReason, cb.captureCount()));

		if (!cb.mmioMockLog.isEmpty()) {
			StringBuilder mockSummary = new StringBuilder();
			mockSummary.append(NAME).append(": MMIO mock activity (first ")
				.append(Math.min(20, cb.mmioMockLog.size())).append(" entries):");
			int n = 0;
			for (String s : cb.mmioMockLog) {
				if (n++ >= 20) break;
				mockSummary.append("\n  ").append(s);
			}
			Msg.info(this, mockSummary.toString());
		}

		// Writes that landed in already-initialized blocks are useful for
		// verifying ROM extent (a true ROM region should see zero such writes).
		if (!cb.writesInInitialized.isEmpty()) {
			StringBuilder romSummary = new StringBuilder();
			romSummary.append(String.format(
				"%s: Trace also observed %d byte(s) of write activity in already-" +
					"initialized blocks (typically ROM-style regions).  First %d " +
					"sample target(s):",
				NAME, cb.writesInInitialized.size(),
				Math.min(10, cb.writesInInitializedSamples.size())));
			for (String s : cb.writesInInitializedSamples) {
				romSummary.append("\n  ").append(s);
			}
			Msg.info(this, romSummary.toString());
		}

		int bytesApplied = applyCaptures(program, cb, log);
		Msg.info(this, String.format("%s: Applied %d byte(s) to %d block(s).",
			NAME, bytesApplied, uninit.size()));

		if (bytesApplied > 0) {
			program.getBookmarkManager().setBookmark(resetAddr,
				BookmarkType.ANALYSIS, BOOKMARK_CATEGORY,
				String.format("Init trace applied %d byte(s) of data; ran for %d step(s).",
					bytesApplied, steps));
		}
		return true;
	}

	private static String describeBlocks(List<MemoryBlock> blocks) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < blocks.size(); i++) {
			if (i > 0) sb.append(", ");
			MemoryBlock b = blocks.get(i);
			sb.append(b.getName()).append(" [").append(b.getStart()).append("..")
				.append(b.getEnd()).append("]");
		}
		return sb.toString();
	}

	private static Address parseHex(String raw, AddressSpace space) {
		if (raw == null || raw.trim().isEmpty()) return null;
		raw = raw.trim();
		if (raw.startsWith("0x") || raw.startsWith("0X")) raw = raw.substring(2);
		try {
			long v = Long.parseLong(raw, 16);
			return space.getAddress(v);
		}
		catch (NumberFormatException e) {
			return null;
		}
	}

	private static Address resolveResetAddress(Program program, String raw,
			AddressSpace space, MessageLog log) {
		Address explicit = parseHex(raw, space);
		if (explicit != null) {
			return explicit;
		}

		SymbolTable st = program.getSymbolTable();
		String[] candidates = { "Reset", "RESET", "_start", "_RESET", "reset" };
		for (String n : candidates) {
			List<Symbol> ss = st.getGlobalSymbols(n);
			if (!ss.isEmpty()) {
				return ss.get(0).getAddress();
			}
		}

		Address zero = space.getAddress(0);
		if (program.getMemory().contains(zero)
			&& program.getListing().getInstructionAt(zero) != null) {
			return zero;
		}
		return null;
	}

	// Seed registers that the listing tracks but the emulator would otherwise
	// treat as uninitialized (itb, IFC_ON, gp).
	private static void seedContextRegisters(Program program, PcodeEmulator emu) {
		ProgramContext pc = program.getProgramContext();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		String[] regs = { "itb", "IFC_ON", "gp" };
		PcodeThread<byte[]> th = null;
		for (String name : regs) {
			Register r = program.getLanguage().getRegister(name);
			if (r == null) {
				continue;
			}
			RegisterValue rv = pc.getRegisterValue(r, space.getAddress(0));
			if (rv == null || !rv.hasValue()) {
				continue;
			}
			if (th == null) {
				th = emu.newThread("seed");
			}
			try {
				byte[] bytes = bigintToBytes(rv.getUnsignedValue(), r.getMinimumByteSize(),
					program.getLanguage().isBigEndian());
				th.getState().setVar(r, bytes);
			}
			catch (Exception e) {
				Msg.warn(NDS32DataInitAnalyzer.class,
					"Could not seed " + name + ": " + e.getMessage());
			}
		}
	}

	private static byte[] bigintToBytes(BigInteger v, int size, boolean bigEndian) {
		byte[] full = v.toByteArray();
		byte[] out = new byte[size];
		int copy = Math.min(full.length, size);
		System.arraycopy(full, full.length - copy, out, size - copy, copy);
		if (!bigEndian) {
			byte[] le = new byte[size];
			for (int i = 0; i < size; i++) {
				le[i] = out[size - 1 - i];
			}
			return le;
		}
		return out;
	}

	private int applyCaptures(Program program, CaptureCallbacks cb, MessageLog log) {
		Memory mem = program.getMemory();
		Listing listing = program.getListing();
		int totalBytes = 0;
		// Track which blocks were converted from uninit -> init in this pass.
		// After conversion isInitialized() returns true; without this set the
		// naive check would skip every subsequent capture in the same block.
		java.util.Set<String> convertedBlockNames = new java.util.HashSet<>();
		for (Map.Entry<Long, byte[]> e : cb.consolidated().entrySet()) {
			long offset = e.getKey();
			byte[] bytes = e.getValue();
			AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
			Address start = space.getAddress(offset);
			MemoryBlock block = mem.getBlock(start);
			if (block == null) {
				continue;
			}
			if (!block.isInitialized()) {
				try {
					MemoryBlock initialized =
						mem.convertToInitialized(block, (byte) 0);
					if (initialized != null) {
						block = initialized;
					}
					convertedBlockNames.add(block.getName());
				}
				catch (Exception ex) {
					Msg.warn(this, "Could not convert block " + block.getName() +
						" to initialized: " + ex.getMessage());
					continue;
				}
			}
			else if (!convertedBlockNames.contains(block.getName())) {
				// Block was already initialized before this run (loaded ROM):
				// skip to avoid clobbering authoritative bytes.
				continue;
			}
			try {
				Address end = start.add(bytes.length - 1);
				listing.clearCodeUnits(start, end, false);
				mem.setBytes(start, bytes);
				totalBytes += bytes.length;
			}
			catch (Exception ex) {
				Msg.warn(this, "Failed to write " + bytes.length + " bytes at " +
					start + ": " + ex.getMessage());
			}
		}
		return totalBytes;
	}

	private enum MockType { CONST, COUNTER, SATURATING_COUNTER }

	private static final class MmioMock {
		final MockType type;
		final long base;     // CONST: returned value; COUNTER: starting value.
		final long step;     // COUNTER: increment per read; CONST: ignored.
		long current;
		long reads;

		MmioMock(MockType t, long base, long step) {
			this.type = t;
			this.base = base;
			this.step = step;
			this.current = base;
		}

		long nextValue() {
			reads++;
			switch (type) {
				case CONST:
					return base;
				case COUNTER: {
					long v = current;
					current += step;
					return v;
				}
				case SATURATING_COUNTER: {
					// 0x10000000 step lets bltz-style polling fall through after 8 reads
					// (high bit set); capped at 0xFFFFFFFF for counter-comparison loops.
					long v = Math.min(current, 0xFFFFFFFFL);
					current += 0x10000000L;
					return v;
				}
			}
			return 0;
		}
	}

	private static Map<Long, MmioMock> parseMmioOverrides(String raw, MessageLog log) {
		Map<Long, MmioMock> out = new HashMap<>();
		if (raw == null || raw.isBlank()) return out;
		for (String entry : raw.split(",")) {
			String s = entry.trim();
			if (s.isEmpty()) continue;
			int eq = s.indexOf('=');
			if (eq < 0) {
				log.appendMsg(NAME, "Ignoring MMIO override (no '='): " + s);
				continue;
			}
			String addrPart = s.substring(0, eq).trim();
			String behPart = s.substring(eq + 1).trim();
			long addr;
			try {
				addr = parseHexLong(addrPart);
			} catch (NumberFormatException e) {
				log.appendMsg(NAME, "Ignoring MMIO override (bad address): " + s);
				continue;
			}
			MmioMock mock = parseBehavior(behPart);
			if (mock == null) {
				log.appendMsg(NAME, "Ignoring MMIO override (bad behavior): " + s);
				continue;
			}
			out.put(addr, mock);
		}
		return out;
	}

	private static MmioMock parseBehavior(String b) {
		String[] parts = b.split(":");
		if (parts.length < 1) return null;
		String kind = parts[0].toLowerCase();
		try {
			if ("const".equals(kind) && parts.length == 2) {
				return new MmioMock(MockType.CONST, parseHexLong(parts[1]), 0);
			}
			if ("count".equals(kind) || "counter".equals(kind)) {
				long step = parts.length >= 2 ? parseHexLong(parts[1]) : 1L;
				return new MmioMock(MockType.COUNTER, 0, step);
			}
		} catch (NumberFormatException e) {
			return null;
		}
		return null;
	}

	private static long parseHexLong(String s) {
		s = s.trim();
		if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
		return Long.parseUnsignedLong(s, 16);
	}

	// Lazily seed reads from the program image and capture writes to the sink range.
	private static final class CaptureCallbacks implements PcodeEmulationCallbacks<byte[]> {
		final Program program;
		final AddressSetView sinkRange;
		final TreeMap<Long, byte[]> writes = new TreeMap<>();
		// Diagnostic: writes to initialized blocks (likely ROM).
		final TreeSet<Long> writesInInitialized = new TreeSet<>();
		final List<String> writesInInitializedSamples = new ArrayList<>();

		Map<Long, MmioMock> mmioMocks;
		boolean mmioAutodetect;
		boolean bigEndian;
		// addr -> [readCount, firstStep, lastStep]
		final HashMap<Long, long[]> mmioReadStats = new HashMap<>();
		long stepCounter;
		final List<String> mmioMockLog = new ArrayList<>();

		CaptureCallbacks(Program program, AddressSetView sinkRange) {
			this.program = program;
			this.sinkRange = sinkRange;
		}

		void installMmioMocks(Map<Long, MmioMock> userMocks, boolean autodetect,
				boolean bigEndian) {
			this.mmioMocks = new HashMap<>(userMocks);
			this.mmioAutodetect = autodetect;
			this.bigEndian = bigEndian;
			for (Map.Entry<Long, MmioMock> e : userMocks.entrySet()) {
				mmioMockLog.add(String.format("user-config 0x%x = %s",
					e.getKey(), describe(e.getValue())));
			}
		}

		private static String describe(MmioMock m) {
			switch (m.type) {
				case CONST: return String.format("const(0x%x)", m.base);
				case COUNTER: return String.format("counter(step=0x%x)", m.step);
				case SATURATING_COUNTER: return "saturating-counter";
			}
			return "?";
		}

		int captureCount() {
			return writes.size();
		}

		// Merge adjacent single-byte writes into contiguous ranges.
		Map<Long, byte[]> consolidated() {
			TreeMap<Long, byte[]> out = new TreeMap<>();
			Long curStart = null;
			ByteArrayOutputStream cur = new ByteArrayOutputStream();
			for (Map.Entry<Long, byte[]> e : writes.entrySet()) {
				if (curStart == null) {
					curStart = e.getKey();
					cur.writeBytes(e.getValue());
					continue;
				}
				long expected = curStart + cur.size();
				if (e.getKey() == expected) {
					cur.writeBytes(e.getValue());
				}
				else {
					out.put(curStart, cur.toByteArray());
					curStart = e.getKey();
					cur.reset();
					cur.writeBytes(e.getValue());
				}
			}
			if (curStart != null) {
				out.put(curStart, cur.toByteArray());
			}
			return out;
		}

		@Override
		public void beforeExecuteInstruction(PcodeThread<byte[]> thread,
				Instruction instruction, PcodeProgram prog) {
			stepCounter++;
		}

		@Override
		public void beforeLoad(PcodeThread<byte[]> thread,
				PcodeOp op,
				AddressSpace space, byte[] offset, int size) {
			if (mmioMocks == null) {
				return;
			}
			if (!"ram".equals(space.getName())) {
				return;
			}
			long addr = bytesToLong(offset, bigEndian);
			if (Long.compareUnsigned(addr, MMIO_THRESHOLD) < 0) {
				return;
			}
			MmioMock m = mmioMocks.get(addr);
			if (m == null && mmioAutodetect) {
				long[] s = mmioReadStats.computeIfAbsent(addr,
					k -> new long[] { 0, stepCounter, stepCounter });
				s[0]++;
				s[2] = stepCounter;
				if (s[0] >= AUTODETECT_READ_THRESHOLD
					&& (s[2] - s[1]) <= AUTODETECT_STEP_WINDOW) {
					m = new MmioMock(MockType.SATURATING_COUNTER, 0, 0x10000000L);
					mmioMocks.put(addr, m);
					if (mmioMockLog.size() < 100) {
						mmioMockLog.add(String.format(
							"auto-promoted 0x%x to saturating-counter at step %d (%d reads in %d steps)",
							addr, stepCounter, s[0], s[2] - s[1]));
					}
				}
			}
			if (m == null) {
				return;
			}
			long val = m.nextValue();
			byte[] bytes = longToBytes(val, size, bigEndian);
			try {
				Address a = space.getAddress(addr);
				thread.getState().setVar(a, size, true, bytes);
			}
			catch (Exception e) {
				// best-effort; fall through to the original read
			}
		}

		private static long bytesToLong(byte[] b, boolean be) {
			long v = 0;
			if (be) {
				for (int i = 0; i < b.length; i++) {
					v = (v << 8) | (b[i] & 0xff);
				}
			}
			else {
				for (int i = b.length - 1; i >= 0; i--) {
					v = (v << 8) | (b[i] & 0xff);
				}
			}
			return v;
		}

		private static byte[] longToBytes(long v, int size, boolean be) {
			byte[] out = new byte[size];
			if (be) {
				for (int i = size - 1; i >= 0; i--) {
					out[i] = (byte) (v & 0xff);
					v >>>= 8;
				}
			}
			else {
				for (int i = 0; i < size; i++) {
					out[i] = (byte) (v & 0xff);
					v >>>= 8;
				}
			}
			return out;
		}

		@Override
		public <A, T> void dataWritten(PcodeThread<byte[]> thread,
				PcodeExecutorStatePiece<A, T> piece, Address address, int length, T value) {
			if (!(value instanceof byte[])) {
				return;
			}
			byte[] bytes = (byte[]) value;
			if (sinkRange.contains(address)) {
				// Byte-by-byte so consolidate() can merge into contiguous runs.
				for (int i = 0; i < length && i < bytes.length; i++) {
					writes.put(address.getOffset() + i, new byte[] { bytes[i] });
				}
			}
			else {
				MemoryBlock b = program.getMemory().getBlock(address);
				if (b != null && b.isInitialized()) {
					for (int i = 0; i < length && i < bytes.length; i++) {
						long addr = address.getOffset() + i;
						if (writesInInitialized.add(addr) && writesInInitializedSamples.size() < 10) {
							writesInInitializedSamples.add(String.format("%s in %s",
								address.add(i), b.getName()));
						}
					}
				}
			}
		}

		@Override
		public <A, T> AddressSetView readUninitialized(PcodeThread<byte[]> thread,
				PcodeExecutorStatePiece<A, T> piece, AddressSetView set, Reason reason) {
			// Lazily seed from the program image so we don't pre-load all of ROM.
			PcodeExecutorStatePiece<A, byte[]> bytesPiece =
				PcodeStateCallbacks.checkValueDomain(piece, byte[].class);
			if (bytesPiece == null) {
				return set;
			}
			AddressSet remains = new AddressSet(set);
			Memory mem = program.getMemory();
			for (AddressRange range : set) {
				MemoryBlock b = mem.getBlock(range.getMinAddress());
				if (b == null || !b.isInitialized()) {
					continue;
				}
				int len = (int) Math.min(range.getLength(), 4096);
				byte[] buf = new byte[len];
				try {
					int read = mem.getBytes(range.getMinAddress(), buf);
					if (read <= 0) {
						continue;
					}
					bytesPiece.setVar(range.getMinAddress(), read, true,
						Arrays.copyOf(buf, read));
					remains.delete(range.getMinAddress(),
						range.getMinAddress().add(read - 1));
				}
				catch (Exception e) {
					// executor will pad with zeros
				}
			}
			return remains;
		}
	}
}
