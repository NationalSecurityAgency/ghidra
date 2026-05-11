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

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pcodeInject.InjectEX9IT;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * NDS32 ITB / EX9.IT analyzer.  Discovers the global {@code itb} value by tracing
 * {@code mtusr Ra, itb} writers, propagates it as a default register value so
 * {@link InjectEX9IT} can see it at every ex9.it site, decodes the IT entry for
 * each ex9.it (setting an EOL comment and the implied references/flows), and
 * marks the IT region as a dword array.  Idempotent.
 */
public class NDS32ITBAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "NDS32 ITB / EX9IT";
	private static final String DESCRIPTION =
		"Tracks the NDS32 Instruction-Table-Base register, annotates EX9.IT " +
			"instructions with the effective instruction, fixes references, and " +
			"marks the IT region as data.";
	private static final String PROCESSOR_NAME = "NDS32";

	private static final String EX9IT_MNEMONIC = "ex9.it";
	private static final int IT_ENTRY_LENGTH = 4;
	/** Bookmark category for ITB-related alerts (override detected, etc.). */
	private static final String BOOKMARK_CATEGORY_ITB = "NDS32 ITB";

	private static final String OPT_MANUAL_ITB = "ITB override (hex)";
	private static final String OPT_MANUAL_ITB_DESC =
		"Force a specific ITB value (hex, e.g. 0x25964).  Leave blank to auto-select " +
			"(highest-address mtusr writer wins).";

	private volatile BigInteger manualItbOverride = null;

	public NDS32ITBAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setDefaultEnablement(true);
		// Must run before CODE_ANALYSIS so function discovery and reference creation
		// see correct fall-through and refs at each ex9.it site -- otherwise they
		// bake in the wrong function boundaries based on the placeholder pcode.
		setPriority(AnalysisPriority.DISASSEMBLY.after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME))) {
			return false;
		}
		return program.getLanguage().getRegister("itb") != null;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPT_MANUAL_ITB, "", null, OPT_MANUAL_ITB_DESC);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		String raw = options.getString(OPT_MANUAL_ITB, "");
		manualItbOverride = parseManualItb(raw);
	}

	private static BigInteger parseManualItb(String raw) {
		if (raw == null) return null;
		raw = raw.trim();
		if (raw.isEmpty()) return null;
		try {
			String hex = raw;
			if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.substring(2);
			return new BigInteger(hex, 16);
		}
		catch (NumberFormatException e) {
			return null;
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {

		Register itbReg = program.getLanguage().getRegister("itb");
		if (itbReg == null) {
			return false;
		}

		// Reload on every run -- option may have changed since the last pass.
		Options analOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
		String optName = "NDS32 ITB / EX9IT." + OPT_MANUAL_ITB;
		manualItbOverride = parseManualItb(analOptions.getString(optName, ""));

		// INSTRUCTION_ANALYZER reruns on every disassembly batch.  When the ITB is
		// already tracked, only `set` can introduce new ex9.it sites -- the rest
		// of the program is wasted work.  Defer the expensive size comparison
		// until the cheap checks pass.
		BigInteger trackedItb = readTrackedItb(program, itbReg);
		boolean canRunIncremental = false;
		if (trackedItb != null && set != null && !set.isEmpty()) {
			long halfTotal = program.getMemory()
				.getLoadedAndInitializedAddressSet().getNumAddresses() / 2;
			canRunIncremental = set.getNumAddresses() < halfTotal;
		}

		Ex9ItScan scan = canRunIncremental
			? scanEx9ItSites(program, set, monitor)
			: scanEx9ItSites(program, monitor);

		// Firmware overlays often have two ITB writers (ROM + firmware); the
		// firmware one wins because its writer sits at a higher address.
		// Incremental runs skip discovery: new code rarely introduces a new
		// writer, and the next full pass would catch it anyway.
		List<ItbCandidate> candidates = canRunIncremental
			? Collections.emptyList()
			: discoverAllItbCandidates(program, monitor);

		BookmarkManager bm = program.getBookmarkManager();
		logCandidates(candidates, log);
		bookmarkCandidates(candidates, bm);

		BigInteger newItb = canRunIncremental
			? trackedItb
			: pickActiveItb(candidates, manualItbOverride, log);
		BigInteger oldItb = trackedItb;

		if (newItb == null) {
			if (oldItb == null) {
				log.appendMsg(NAME,
					"Could not determine ITB value; ex9.it sites will not be annotated. " +
						"Set the '" + OPT_MANUAL_ITB + "' analyzer option to override.");
			}
			return true;
		}

		boolean overrideDetected = !canRunIncremental
			&& oldItb != null && !oldItb.equals(newItb);
		if (overrideDetected) {
			handleItbOverride(program, itbReg, oldItb, newItb, candidates, scan, monitor, log);
		}
		else if (oldItb == null) {
			Msg.info(this, String.format(
				"%s: ITB = 0x%08x (chosen from %d candidate(s))",
				NAME, newItb.longValue(), candidates.size()));
		}

		// applyGlobalItb spans the full address space, so skip on incremental runs
		// (value didn't change).  markItbTableAsData also needs the accurate
		// scan.maxImmSeen which incremental scans can't produce.
		if (!canRunIncremental) {
			applyGlobalItb(program, itbReg, newItb, log);
		}

		annotateEx9ItSites(program, newItb.longValue(), scan, monitor, log);

		if (!canRunIncremental) {
			markItbTableAsData(program, newItb.longValue(), scan.maxImmSeen, monitor, log);
		}

		return true;
	}

	private static void logCandidates(List<ItbCandidate> candidates, MessageLog log) {
		if (candidates.isEmpty()) {
			return;
		}
		LinkedHashMap<Long, Address> distinct = new LinkedHashMap<>();
		for (ItbCandidate c : candidates) {
			Long key = c.itb.longValue();
			if (!distinct.containsKey(key)) {
				distinct.put(key, c.writerAddr);
			}
		}
		if (distinct.size() <= 1) {
			return;
		}
		StringBuilder sb = new StringBuilder();
		sb.append("Multiple ITB writers detected:\n");
		for (Map.Entry<Long, Address> e : distinct.entrySet()) {
			sb.append(String.format("  - 0x%08x (first written at %s)%n", e.getKey(), e.getValue()));
		}
		sb.append("Set the '").append(OPT_MANUAL_ITB)
			.append("' analyzer option to choose a specific value (hex).");
		log.appendMsg(NAME, sb.toString());
	}

	private static void bookmarkCandidates(List<ItbCandidate> candidates, BookmarkManager bm) {
		for (ItbCandidate c : candidates) {
			bm.setBookmark(c.writerAddr, BookmarkType.INFO, BOOKMARK_CATEGORY_ITB,
				String.format("ITB writer: 0x%08x", c.itb.longValue()));
		}
	}

	private static final class ItbCandidate {
		final Address writerAddr;
		final BigInteger itb;

		ItbCandidate(Address writerAddr, BigInteger itb) {
			this.writerAddr = writerAddr;
			this.itb = itb;
		}
	}

	// Manual override (honored even when no candidate matches -- ITB may be set
	// by means we can't trace), otherwise the highest-address writer wins
	// (firmware overlays take precedence over the ROM init).
	private static BigInteger pickActiveItb(List<ItbCandidate> candidates,
			BigInteger manualOverride, MessageLog log) {
		if (manualOverride != null) {
			boolean matched = candidates.stream()
				.anyMatch(c -> c.itb.equals(manualOverride));
			if (!matched && !candidates.isEmpty()) {
				log.appendMsg(NAME, String.format(
					"Using manual ITB override 0x%08x; none of the %d " +
						"auto-discovered candidate(s) match this value.",
					manualOverride.longValue(), candidates.size()));
			}
			else if (matched) {
				Msg.info(NDS32ITBAnalyzer.class, String.format(
					"%s: Using manual ITB override 0x%08x.",
					NAME, manualOverride.longValue()));
			}
			return manualOverride;
		}
		if (candidates.isEmpty()) {
			return null;
		}
		ItbCandidate best = candidates.get(0);
		for (ItbCandidate c : candidates) {
			if (c.writerAddr.compareTo(best.writerAddr) > 0) {
				best = c;
			}
		}
		return best.itb;
	}

	/**
	 * Re-analyze every ex9.it site under the new ITB, log the IT-entry diff,
	 * and place bookmarks at each site whose effective instruction changed.
	 */
	private void handleItbOverride(Program program, Register itbReg, BigInteger oldItb,
			BigInteger newItb, List<ItbCandidate> candidates, Ex9ItScan scan,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		Msg.info(this, String.format(
			"%s: ITB override: was 0x%08x, now 0x%08x; re-analyzing %d ex9.it site(s)",
			NAME, oldItb.longValue(), newItb.longValue(), scan.sites.size()));

		Address newWriter = null;
		for (ItbCandidate c : candidates) {
			if (c.itb.equals(newItb)) {
				if (newWriter == null || c.writerAddr.compareTo(newWriter) > 0) {
					newWriter = c.writerAddr;
				}
			}
		}
		BookmarkManager bm = program.getBookmarkManager();
		if (newWriter != null) {
			bm.setBookmark(newWriter, BookmarkType.WARNING, BOOKMARK_CATEGORY_ITB,
				String.format("ITB override detected: 0x%08x -> 0x%08x; all ex9.it sites" +
					" are being re-analyzed against the new table",
					oldItb.longValue(), newItb.longValue()));
		}

		Map<Long, String> oldEntries = decodeAllUsedEntries(program, oldItb.longValue(), scan);
		Map<Long, String> newEntries = decodeAllUsedEntries(program, newItb.longValue(), scan);
		logItEntryDiff(oldEntries, newEntries);
		bookmarkChangedSites(program, scan, oldItb.longValue(), newItb.longValue(),
			oldEntries, newEntries, bm);

		// Drop the pcode-injection cache so decompile sees the new IT table.
		try {
			InjectPayload payload = program.getCompilerSpec().getPcodeInjectLibrary()
				.getPayload(InjectPayload.CALLOTHERFIXUP_TYPE, "ex9");
			if (payload instanceof InjectEX9IT) {
				((InjectEX9IT) payload).invalidateCache(program);
			}
		}
		catch (Exception e) {
			Msg.warn(this, "Could not invalidate ex9 pcode cache: " + e.getMessage());
		}

		// Clear stale EOL comments so re-annotation reflects only the new state.
		Listing listing = program.getListing();
		for (Ex9ItSite site : scan.sites) {
			monitor.checkCancelled();
			listing.setComment(site.addr, CodeUnit.EOL_COMMENT, null);
		}
	}

	// Keyed on imm (not site address): sites sharing an imm decode to the same entry.
	private Map<Long, String> decodeAllUsedEntries(Program program, long itbBase, Ex9ItScan scan) {
		Map<Long, String> out = new LinkedHashMap<>();
		Language lang = program.getLanguage();
		ProgramContext pc = program.getProgramContext();
		Memory mem = program.getMemory();
		long base = itbBase & ~0b11L;
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		HashSet<Long> seen = new HashSet<>();
		for (Ex9ItSite site : scan.sites) {
			if (!seen.add(site.imm)) {
				continue;
			}
			Address entryAddr;
			try {
				entryAddr = space.getAddress(base + site.imm * IT_ENTRY_LENGTH);
			}
			catch (Exception e) {
				out.put(site.imm, "(unmapped)");
				continue;
			}
			byte[] bytes = new byte[IT_ENTRY_LENGTH];
			try {
				if (mem.getBytes(entryAddr, bytes) != Array.getLength(bytes)) {
					out.put(site.imm, "(unmapped)");
					continue;
				}
			}
			catch (Exception e) {
				out.put(site.imm, "(unmapped)");
				continue;
			}
			PseudoInstruction effective =
				decodeItEntryAtSite(program, lang, pc, site.addr, bytes);
			out.put(site.imm, effective != null ? formatInstruction(effective) : "(undecodable)");
		}
		return out;
	}

	private static void logItEntryDiff(Map<Long, String> oldMap, Map<Long, String> newMap) {
		int changed = 0;
		int added = 0;
		int removed = 0;
		int same = 0;
		StringBuilder details = new StringBuilder();
		TreeSet<Long> keys = new TreeSet<>(oldMap.keySet());
		keys.addAll(newMap.keySet());
		for (Long k : keys) {
			String o = oldMap.get(k);
			String n = newMap.get(k);
			if (o == null) {
				added++;
				details.append(String.format("  IT[%d]: (none) -> %s%n", k, n));
			}
			else if (n == null) {
				removed++;
				details.append(String.format("  IT[%d]: %s -> (none)%n", k, o));
			}
			else if (!o.equals(n)) {
				changed++;
				details.append(String.format("  IT[%d]: %s -> %s%n", k, o, n));
			}
			else {
				same++;
			}
		}
		Msg.info(NDS32ITBAnalyzer.class, String.format(
			"%s: IT entry diff: %d changed, %d added, %d removed, %d unchanged",
			NAME, changed, added, removed, same));
		if (details.length() > 0) {
			Msg.info(NDS32ITBAnalyzer.class, NAME + ": IT entry changes:\n" + details.toString());
		}
	}

	private void bookmarkChangedSites(Program program, Ex9ItScan scan,
			long oldItbBase, long newItbBase,
			Map<Long, String> oldEntries, Map<Long, String> newEntries, BookmarkManager bm) {
		Map<Long, byte[]> oldBytes = readItEntryBytes(program, oldItbBase, scan);
		Map<Long, byte[]> newBytes = readItEntryBytes(program, newItbBase, scan);
		for (Ex9ItSite site : scan.sites) {
			byte[] ob = oldBytes.get(site.imm);
			byte[] nb = newBytes.get(site.imm);
			if (ob != null && nb != null && Arrays.equals(ob, nb)) {
				// Identical IT entry bytes -- the override moved the table base
				// but this entry's content is unchanged.  No bookmark.
				continue;
			}
			String o = oldEntries.get(site.imm);
			String n = newEntries.get(site.imm);
			if (o != null && n != null && !o.equals(n)) {
				bm.setBookmark(site.addr, BookmarkType.INFO, BOOKMARK_CATEGORY_ITB,
					String.format("ITB override re-mapped this site: %s -> %s", o, n));
			}
		}
	}

	// Returns imm -> raw IT entry bytes for every unique imm in scan.  Entries
	// that fall outside loaded memory are simply omitted from the map.
	private static Map<Long, byte[]> readItEntryBytes(Program program, long itbBase,
			Ex9ItScan scan) {
		Map<Long, byte[]> out = new LinkedHashMap<>();
		Memory mem = program.getMemory();
		long base = itbBase & ~0b11L;
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		HashSet<Long> seen = new HashSet<>();
		for (Ex9ItSite site : scan.sites) {
			if (!seen.add(site.imm)) {
				continue;
			}
			try {
				Address entryAddr = space.getAddress(base + site.imm * IT_ENTRY_LENGTH);
				byte[] bytes = new byte[IT_ENTRY_LENGTH];
				if (mem.getBytes(entryAddr, bytes) == bytes.length) {
					out.put(site.imm, bytes);
				}
			}
			catch (Exception e) {
				// leave imm out of map; bookmark logic will fall through to
				// decode-string comparison
			}
		}
		return out;
	}

	/**
	 * Read the first concrete ITB value found in the program context, or null.
	 * The ITB value is treated as global so any tracked range suffices.
	 */
	private static BigInteger readTrackedItb(Program program, Register itbReg) {
		ProgramContext pc = program.getProgramContext();
		var ranges = pc.getRegisterValueAddressRanges(itbReg);
		while (ranges.hasNext()) {
			var range = ranges.next();
			RegisterValue rv = pc.getRegisterValue(itbReg, range.getMinAddress());
			if (rv != null && rv.hasValue()) {
				return rv.getUnsignedValue();
			}
		}
		return null;
	}

	private static class Ex9ItSite {
		final Address addr;
		final long imm;

		Ex9ItSite(Address addr, long imm) {
			this.addr = addr;
			this.imm = imm;
		}
	}

	private static class Ex9ItScan {
		final List<Ex9ItSite> sites = new ArrayList<>();
		long maxImmSeen = -1;
	}

	private static Ex9ItScan scanEx9ItSites(Program program, TaskMonitor monitor)
			throws CancelledException {
		return scanEx9ItSites(program, null, monitor);
	}

	// Restrict to a subset on incremental runs; full scan otherwise.
	private static Ex9ItScan scanEx9ItSites(Program program, AddressSetView restrict,
			TaskMonitor monitor) throws CancelledException {
		Ex9ItScan scan = new Ex9ItScan();
		Iterable<Instruction> iter = (restrict != null && !restrict.isEmpty())
			? () -> program.getListing().getInstructions(restrict, true)
			: () -> program.getListing().getInstructions(true);
		for (Instruction insn : iter) {
			monitor.checkCancelled();
			if (!insn.getMnemonicString().equalsIgnoreCase(EX9IT_MNEMONIC)) {
				continue;
			}
			Scalar s = insn.getScalar(0);
			if (s == null) {
				continue;
			}
			long imm = s.getUnsignedValue();
			scan.sites.add(new Ex9ItSite(insn.getAddress(), imm));
			if (imm > scan.maxImmSeen) {
				scan.maxImmSeen = imm;
			}
		}
		return scan;
	}

	/**
	 * Walk every {@code mtusr Ra, itb} writer and trace the constant flowing
	 * into Ra.  Returns every (writer address, value) pair so the caller can
	 * pick the active one and report on overrides.
	 */
	private static List<ItbCandidate> discoverAllItbCandidates(Program program,
			TaskMonitor monitor) throws CancelledException {
		List<ItbCandidate> out = new ArrayList<>();
		for (Instruction insn : program.getListing().getInstructions(true)) {
			monitor.checkCancelled();
			if (!insn.getMnemonicString().equalsIgnoreCase("mtusr")) {
				continue;
			}
			if (!operandIsItb(insn)) {
				continue;
			}
			BigInteger v = traceConstantWrittenToFirstOperand(insn, program);
			if (v == null) {
				continue;
			}
			// Hardware forces the low two bits to zero; canonicalize and
			// reject obvious junk (mov-zero, very small constants).
			long lv = v.longValue() & 0xFFFFFFFFL;
			if (lv < 0x100) {
				continue;
			}
			long aligned = lv & ~0b11L;
			if (aligned != lv) {
				v = BigInteger.valueOf(aligned);
			}
			out.add(new ItbCandidate(insn.getAddress(), v));
		}
		return out;
	}

	private static boolean operandIsItb(Instruction insn) {
		Register r = insn.getRegister(1);
		return r != null && r.getName().equalsIgnoreCase("itb");
	}

	/**
	 * Walk back up to 16 instructions to find the constant written into the source
	 * register of {@code mtusrInsn}.  Recognizes {@code movi}, {@code sethi[+ori]},
	 * and {@code lwi.gp/lw} loads of constants from program memory (the shape MT7663
	 * uses to read its ITB from a .data slot).  Intervening {@code addi} adjustments
	 * to the same register are accumulated.
	 */
	private static BigInteger traceConstantWrittenToFirstOperand(Instruction mtusrInsn,
			Program program) {
		Register src = mtusrInsn.getRegister(0);
		if (src == null) {
			return null;
		}
		long hi = -1;
		long lo = -1;
		long adjust = 0;
		Instruction cur = mtusrInsn.getPrevious();
		for (int i = 0; cur != null && i < 16; cur = cur.getPrevious(), i++) {
			String m = cur.getMnemonicString();
			Register dst = cur.getRegister(0);
			if (dst == null || !dst.equals(src)) {
				continue;
			}
			if (m.equals("addi") || m.equals("addi.gp") || m.equals("addi333")) {
				Scalar s = lastScalar(cur);
				if (s == null) {
					return null;
				}
				adjust += s.getSignedValue();
				continue;
			}
			if (m.equals("movi")) {
				Scalar s = cur.getScalar(1);
				if (s == null) {
					return null;
				}
				return BigInteger.valueOf((s.getSignedValue() + adjust) & 0xffffffffL);
			}
			if (m.equals("ori")) {
				Scalar s = cur.getScalar(2);
				if (s == null) {
					return null;
				}
				lo = s.getUnsignedValue();
				continue;
			}
			if (m.equals("sethi")) {
				Scalar s = cur.getScalar(1);
				if (s == null) {
					return null;
				}
				hi = s.getUnsignedValue() << 12;
				break;
			}
			if (m.startsWith("lwi") || m.equals("lw")) {
				Long loaded = readWordLoad(program, cur);
				if (loaded == null) {
					return null;
				}
				return BigInteger.valueOf((loaded + adjust) & 0xffffffffL);
			}
			return null;
		}
		if (hi == -1) {
			return null;
		}
		long val = hi | (lo == -1 ? 0 : lo);
		return BigInteger.valueOf((val + adjust) & 0xffffffffL);
	}

	// Instruction.getScalar(int) misses scalars nested in memory operands like
	// [+ -0x2c018]; walk operand objects directly to recover the last one.
	private static Scalar lastScalar(Instruction insn) {
		for (int i = insn.getNumOperands() - 1; i >= 0; i--) {
			Object[] objs = insn.getOpObjects(i);
			for (int j = objs.length - 1; j >= 0; j--) {
				if (objs[j] instanceof Scalar) {
					return (Scalar) objs[j];
				}
			}
		}
		return null;
	}

	/**
	 * Read the 4-byte memory slot referenced by a word-load whose effective
	 * address can be resolved from tracked register values.  Returns null if
	 * the load can't be resolved.
	 */
	private static Long readWordLoad(Program program, Instruction loadInsn) {
		String m = loadInsn.getMnemonicString();
		Register baseReg = m.endsWith(".gp")
			? program.getLanguage().getRegister("gp")
			: loadInsn.getRegister(1);
		if (baseReg == null) {
			return null;
		}
		ProgramContext pc = program.getProgramContext();
		RegisterValue rv = pc.getRegisterValue(baseReg, loadInsn.getAddress());
		if (rv == null || !rv.hasValue()) {
			return null;
		}
		long base = rv.getUnsignedValue().longValue() & 0xFFFFFFFFL;
		Scalar offScalar = lastScalar(loadInsn);
		long offset = offScalar == null ? 0 : offScalar.getSignedValue();
		long effective = (base + offset) & 0xFFFFFFFFL;
		try {
			Address ea = program.getAddressFactory().getDefaultAddressSpace()
				.getAddress(effective);
			// Reject uninitialized SRAM slots -- they'd read as zero and propagate
			// as a bogus ITB candidate.
			MemoryBlock block = program.getMemory().getBlock(ea);
			if (block == null || !block.isInitialized()) {
				return null;
			}
			byte[] buf = new byte[4];
			if (program.getMemory().getBytes(ea, buf) != 4) {
				return null;
			}
			boolean be = program.getLanguage().isBigEndian();
			long v = be
				? (((buf[0] & 0xffL) << 24) | ((buf[1] & 0xffL) << 16)
				   | ((buf[2] & 0xffL) << 8) | (buf[3] & 0xffL))
				: ((buf[0] & 0xffL) | ((buf[1] & 0xffL) << 8)
				   | ((buf[2] & 0xffL) << 16) | ((buf[3] & 0xffL) << 24));
			return v;
		}
		catch (Exception e) {
			return null;
		}
	}

	/**
	 * Set the discovered ITB as a default register value across the entire address
	 * space so every code unit that hits the pcode fixup sees it.
	 */
	private void applyGlobalItb(Program program, Register itbReg, BigInteger itb,
			MessageLog log) {
		ProgramContext pc = program.getProgramContext();
		AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
		Address lo = defaultSpace.getMinAddress();
		Address hi = defaultSpace.getMaxAddress();
		try {
			pc.setRegisterValue(lo, hi, new RegisterValue(itbReg, itb));
			Msg.info(this, String.format(
				"%s: ITB = 0x%08x (set program-wide)", NAME, itb.longValue()));
		}
		catch (ContextChangeException e) {
			log.appendException(e);
		}
	}

	/**
	 * For each ex9.it site, decode the IT entry, set an EOL comment, and rewrite
	 * references to match the effective instruction's flow.
	 */
	private void annotateEx9ItSites(Program program, long itbBase, Ex9ItScan scan,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		Language lang = program.getLanguage();
		ProgramContext pc = program.getProgramContext();
		Memory mem = program.getMemory();
		Listing listing = program.getListing();
		ReferenceManager refMgr = program.getReferenceManager();

		// Share the parse cache with the pcode-injection layer.
		InjectEX9IT injector = null;
		try {
			InjectPayload payload = program.getCompilerSpec().getPcodeInjectLibrary()
				.getPayload(InjectPayload.CALLOTHERFIXUP_TYPE, "ex9");
			if (payload instanceof InjectEX9IT) {
				injector = (InjectEX9IT) payload;
			}
		}
		catch (Exception e) {
			injector = null;
		}

		long base = itbBase & ~0b11L;
		// Auto-analysis often misses refs we add post-hoc; collect flow targets
		// for an explicit disassembly pass, and call targets for function promotion
		// (SubroutineReferenceAnalyzer treats ex9.it as fall-through).
		AddressSet flowTargets = new AddressSet();
		AddressSet callTargets = new AddressSet();

		BookmarkManager bm = program.getBookmarkManager();
		// Clear stale validation bookmarks so re-runs reflect current state.
		for (Ex9ItSite site : scan.sites) {
			monitor.checkCancelled();
			Bookmark[] existing = bm.getBookmarks(site.addr, BookmarkType.WARNING);
			for (Bookmark b : existing) {
				if (BOOKMARK_CATEGORY_ITB.equals(b.getCategory())
					&& b.getComment() != null
					&& b.getComment().startsWith("Invalid IT entry:")) {
					bm.removeBookmark(b);
				}
			}
		}

		for (Ex9ItSite site : scan.sites) {
			monitor.checkCancelled();
			Address entryAddr = site.addr.getNewAddress(base + site.imm * IT_ENTRY_LENGTH);
			byte[] bytes = new byte[IT_ENTRY_LENGTH];
			boolean unmapped = false;
			try {
				if (mem.getBytes(entryAddr, bytes) != Array.getLength(bytes)) {
					unmapped = true;
				}
			}
			catch (Exception e) {
				unmapped = true;
			}
			if (unmapped) {
				bm.setBookmark(site.addr, BookmarkType.WARNING, BOOKMARK_CATEGORY_ITB,
					String.format("Invalid IT entry: imm=%d -> %s is unmapped (ITB=0x%08x)",
						site.imm, entryAddr, itbBase));
				continue;
			}

			DecodeResult result = decodeItEntryCached(program, lang, pc, injector,
				site.addr, entryAddr, bytes);
			if (result.status == Status.RECURSIVE) {
				bm.setBookmark(site.addr, BookmarkType.WARNING, BOOKMARK_CATEGORY_ITB,
					String.format("Invalid IT entry: imm=%d -> nested ex9.it at %s " +
						"(hardware would raise Reserved Instruction Exception)",
						site.imm, entryAddr));
				continue;
			}
			if (result.status != Status.OK || result.instruction == null) {
				bm.setBookmark(site.addr, BookmarkType.WARNING, BOOKMARK_CATEGORY_ITB,
					String.format("Invalid IT entry: imm=%d -> %s bytes do not decode to a " +
						"valid instruction (data padding in table?)", site.imm, entryAddr));
				continue;
			}
			PseudoInstruction effective = result.instruction;

			String repr = formatInstruction(effective);
			// setComment round-trips through the listing DB even on no-ops; skip
			// the write when the existing comment already matches.
			String existingComment = listing.getComment(CodeUnit.EOL_COMMENT, site.addr);
			if (!repr.equals(existingComment)) {
				listing.setComment(site.addr, CodeUnit.EOL_COMMENT, repr);
			}

			rewriteReferences(program, refMgr, site.addr, effective, flowTargets, callTargets);
		}

		// Run inside this pass so the rest of CODE_ANALYSIS sees the new instructions.
		disassembleNewTargets(program, flowTargets, monitor, log);
		promoteCallTargets(program, callTargets, monitor, log);
	}

	private void promoteCallTargets(Program program, AddressSet callTargets,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		if (callTargets.isEmpty()) {
			return;
		}
		var fm = program.getFunctionManager();
		Listing listing = program.getListing();
		int created = 0;
		for (Address a : callTargets.getAddresses(true)) {
			monitor.checkCancelled();
			if (fm.getFunctionAt(a) != null) {
				continue;
			}
			if (listing.getInstructionAt(a) == null) {
				continue;
			}
			CreateFunctionCmd cmd = new CreateFunctionCmd(a);
			if (cmd.applyTo(program, monitor)) {
				created++;
			}
		}
		if (created > 0) {
			Msg.info(this, String.format(
				"%s: Promoted %d ex9.it call target(s) to Function", NAME, created));
		}
	}

	private void disassembleNewTargets(Program program, AddressSet flowTargets,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		Listing listing = program.getListing();
		Memory mem = program.getMemory();
		AddressSet toDisasm = new AddressSet();
		for (Address a : flowTargets.getAddresses(true)) {
			monitor.checkCancelled();
			if (!mem.contains(a)) {
				continue;
			}
			if (listing.getInstructionAt(a) != null) {
				continue;
			}
			if (listing.getDefinedDataAt(a) != null) {
				continue;
			}
			toDisasm.add(a);
		}
		if (toDisasm.isEmpty()) {
			return;
		}
		for (var range : toDisasm.getAddressRanges()) {
			monitor.checkCancelled();
			DisassembleCommand cmd = new DisassembleCommand(range.getMinAddress(), null, true);
			cmd.applyTo(program, monitor);
		}
		Msg.info(this, String.format(
			"%s: Triggered disassembly at %d ex9.it-only flow target(s)",
			NAME, toDisasm.getNumAddresses()));
	}

	enum Status { OK, UNDECODABLE, RECURSIVE }

	private static final class DecodeResult {
		final Status status;
		final PseudoInstruction instruction;

		DecodeResult(Status status, PseudoInstruction instruction) {
			this.status = status;
			this.instruction = instruction;
		}
	}

	/**
	 * Reuses the pcode-injector's parse cache to avoid re-parsing each unique IT
	 * entry across thousands of ex9.it sites.  Falls back to the uncached path
	 * when the injector isn't available, and when lookupOrParse returns null
	 * (so the bookmark message can identify the specific reason).
	 */
	private static DecodeResult decodeItEntryCached(Program program, Language lang,
			ProgramContext pc, InjectEX9IT injector, Address site, Address entryAddr,
			byte[] bytes) {
		if (injector == null) {
			return decodeItEntryAtSiteFull(program, lang, pc, site, bytes);
		}
		try {
			InjectEX9IT.CacheEntry entry = injector.lookupOrParse(program, pc, lang,
				entryAddr, bytes);
			if (entry == null) {
				return decodeItEntryAtSiteFull(program, lang, pc, site, bytes);
			}
			PseudoDisassemblerContext disCtx = new PseudoDisassemblerContext(pc);
			MemBuffer buf = new ByteMemBufferImpl(site, entry.bytes, lang.isBigEndian());
			disCtx.flowStart(site);
			Address rebuildAt = entry.rebuildAtZero
				? program.getAddressFactory().getDefaultAddressSpace().getAddress(0)
				: site;
			PseudoInstruction probe = entry.rebuildAtZero
				? new PseudoInstruction(program.getAddressFactory(), rebuildAt,
					entry.proto, buf, disCtx)
				: new PseudoInstruction(program, rebuildAt, entry.proto, buf, disCtx);
			return new DecodeResult(Status.OK, probe);
		}
		catch (AddressOverflowException e) {
			return new DecodeResult(Status.UNDECODABLE, null);
		}
		catch (Exception e) {
			return new DecodeResult(Status.UNDECODABLE, null);
		}
	}

	private static DecodeResult decodeItEntryAtSiteFull(Program program, Language lang,
			ProgramContext pc, Address site, byte[] bytes) {
		try {
			PseudoDisassemblerContext disCtx = new PseudoDisassemblerContext(pc);
			MemBuffer buf = new ByteMemBufferImpl(site, bytes, lang.isBigEndian());
			disCtx.flowStart(site);
			InstructionPrototype proto = lang.parse(buf, disCtx, false);
			if (proto == null) {
				return new DecodeResult(Status.UNDECODABLE, null);
			}
			// Hardware raises Reserved Instruction Exception for nested ex9.it.
			PseudoInstruction probe = new PseudoInstruction(program, site, proto, buf, disCtx);
			if (probe.getMnemonicString().equalsIgnoreCase(EX9IT_MNEMONIC)) {
				return new DecodeResult(Status.RECURSIVE, null);
			}
			FlowType ft = proto.getFlowType(probe);
			if (ft.isCall() || ft.isJump()) {
				// Branches via ex9.it decode as if PC=0 per the NDS32 manual.
				Address zero = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
				return new DecodeResult(Status.OK,
					new PseudoInstruction(program.getAddressFactory(), zero, proto, buf, disCtx));
			}
			return new DecodeResult(Status.OK, probe);
		}
		catch (AddressOverflowException e) {
			return new DecodeResult(Status.UNDECODABLE, null);
		}
		catch (Exception e) {
			return new DecodeResult(Status.UNDECODABLE, null);
		}
	}

	private static PseudoInstruction decodeItEntryAtSite(Program program, Language lang,
			ProgramContext pc, Address site, byte[] bytes) {
		return decodeItEntryAtSiteFull(program, lang, pc, site, bytes).instruction;
	}

	private static String formatInstruction(PseudoInstruction insn) {
		StringBuilder sb = new StringBuilder();
		sb.append(insn.getMnemonicString());
		int n = insn.getNumOperands();
		for (int i = 0; i < n; i++) {
			sb.append(i == 0 ? " " : ", ");
			sb.append(insn.getDefaultOperandRepresentation(i));
		}
		return sb.toString();
	}

	// True when the analysis-source refs at the site already match the (to, refType)
	// set implied by the effective instruction.  Used to skip the delete/recreate
	// round-trip on re-runs with unchanged ITB.
	private static boolean referencesAlreadyMatch(Reference[] existing, Reference[] effRefs) {
		HashSet<String> have = new HashSet<>();
		for (Reference r : existing) {
			if (r.getSource() == SourceType.USER_DEFINED) {
				continue;
			}
			have.add(r.getToAddress() + ":" + r.getReferenceType());
		}
		HashSet<String> want = new HashSet<>();
		for (Reference r : effRefs) {
			want.add(r.getToAddress() + ":" + r.getReferenceType());
		}
		return have.equals(want);
	}

	private void rewriteReferences(Program program, ReferenceManager refMgr, Address site,
			PseudoInstruction effective, AddressSet flowTargets, AddressSet callTargets) {
		Reference[] existing = refMgr.getReferencesFrom(site);
		Reference[] effRefs = effective.getReferencesFrom();
		FlowType flow = effective.getFlowType();

		boolean refsAlreadyCorrect = referencesAlreadyMatch(existing, effRefs);
		if (!refsAlreadyCorrect) {
			for (Reference r : existing) {
				if (r.getSource() != SourceType.USER_DEFINED) {
					refMgr.delete(r);
				}
			}
		}
		Instruction siteInsn = program.getListing().getInstructionAt(site);
		if (siteInsn == null) {
			return;
		}
		HashSet<Address> seenTargets = new HashSet<>();
		for (Reference r : effRefs) {
			Address to = r.getToAddress();
			if (!seenTargets.add(to)) {
				continue;
			}
			RefType rt = r.getReferenceType();
			if (!refsAlreadyCorrect) {
				siteInsn.addMnemonicReference(to, rt, SourceType.ANALYSIS);
			}
			if (rt.isFlow()) {
				flowTargets.add(to);
			}
			if (rt.isCall()) {
				callTargets.add(to);
			}
		}
		// Fall back to flow targets when the effective instruction didn't produce refs.
		if (effRefs.length == 0 && flow != null && (flow.isJump() || flow.isCall())) {
			Address[] flows = effective.getFlows();
			if (flows != null) {
				for (Address f : flows) {
					if (seenTargets.add(f)) {
						RefType t = flow.isCall() ? RefType.UNCONDITIONAL_CALL
								: RefType.UNCONDITIONAL_JUMP;
						siteInsn.addMnemonicReference(f, t, SourceType.ANALYSIS);
						flowTargets.add(f);
						if (flow.isCall()) {
							callTargets.add(f);
						}
					}
				}
			}
		}

		// Sleigh models ex9.it as a callother with implicit fall-through; clear it
		// for unconditional jumps so the listing reflects the IT entry's actual flow.
		if (flow != null && flow.isJump() && !flow.isConditional()) {
			siteInsn.setFallThrough(null);
		}
	}

	/**
	 * Mark the IT region as a {@code dword[maxImm+1]} array so analysis does not
	 * generate references from instructions in the table to surrounding code.
	 */
	private void markItbTableAsData(Program program, long itbBase, long maxImm,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		if (maxImm < 0) {
			return;
		}
		Listing listing = program.getListing();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		long base = itbBase & ~0b11L;
		int count = (int) maxImm + 1;
		Address start;
		try {
			start = space.getAddress(base);
		}
		catch (AddressOutOfBoundsException e) {
			return;
		}
		Address end;
		try {
			end = start.addNoWrap(count * IT_ENTRY_LENGTH - 1);
		}
		catch (AddressOverflowException e) {
			return;
		}

		// Skip clear/recreate when a previous run already produced this exact array.
		Data existing = listing.getDataAt(start);
		if (existing != null) {
			DataType dt = existing.getDataType();
			if (dt instanceof ArrayDataType) {
				ArrayDataType existingArr = (ArrayDataType) dt;
				if (existingArr.getNumElements() == count
					&& existingArr.getDataType() instanceof DWordDataType) {
					return;
				}
			}
		}

		// Disassembly may have landed on the table before this analyzer ran.
		AddressSet region = new AddressSet(start, end);
		listing.clearCodeUnits(start, end, false);
		ReferenceManager refMgr = program.getReferenceManager();
		for (Address a : refMgr.getReferenceSourceIterator(region, true)) {
			monitor.checkCancelled();
			for (Reference r : refMgr.getReferencesFrom(a)) {
				refMgr.delete(r);
			}
		}

		DataType dword = new DWordDataType();
		DataType arr = new ArrayDataType(dword, count, dword.getLength());
		try {
			listing.createData(start, arr);
			Msg.info(this, String.format(
				"%s: Marked IT region [0x%08x..0x%08x] as dword[%d]",
				NAME, base, end.getOffset(), count));
		}
		catch (Exception e) {
			Msg.warn(this, "Failed to mark IT region as data: " + e.getMessage());
		}
	}
}
